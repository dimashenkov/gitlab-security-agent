''


















import asyncio
import json
import os
import signal
import time
from functools import wraps
from subprocess import Popen
from urllib.parse import quote, urlparse
from weakref import WeakKeyDictionary

from tornado.httpclient import AsyncHTTPClient, HTTPError, HTTPRequest
from tornado.ioloop import PeriodicCallback
from traitlets import (
    Any,
    Bool,
    CaselessStrEnum,
    Dict,
    Instance,
    Integer,
    TraitError,
    Unicode,
    default,
    observe,
    validate,
)
from traitlets.config import LoggingConfigurable

from jupyterhub.traitlets import Command

from . import utils
from .metrics import CHECK_ROUTES_DURATION_SECONDS, PROXY_POLL_DURATION_SECONDS
from .objects import Server
from .utils import exponential_backoff, url_escape_path, url_path_join


def _one_at_a_time(method):
    ''







    method._locks = WeakKeyDictionary()

    @wraps(method)
    async def locked_method(*args, **kwargs):
        loop = asyncio.get_event_loop()
        lock = method._locks.get(loop, None)
        if lock is None:
            lock = method._locks[loop] = asyncio.Lock()
        async with lock:
            return await method(*args, **kwargs)

    return locked_method


class Proxy(LoggingConfigurable):
    ''






















    db_factory = Any()

    @property
    def db(self):
        return self.db_factory()

    app = Any()
    hub = Any()
    public_url = Unicode()
    ssl_key = Unicode()
    ssl_cert = Unicode()
    host_routing = Bool()

    should_start = Bool(
        True,
        config=True,
        help="""Should the Hub start the proxy

        If True, the Hub will start the proxy and stop it.
        Set to False if the proxy is managed externally,
        such as by systemd, docker, or another service manager.
        """,
    )

    extra_routes = Dict(
        key_trait=Unicode(),
        value_trait=Unicode(),
        config=True,
        help="""
        Additional routes to be maintained in the proxy.

        A dictionary with a route specification as key, and
        a URL as target. The hub will ensure this route is present
        in the proxy.

        If the hub is running in host based mode (with
        JupyterHub.subdomain_host set), the routespec *must*
        have a domain component (example.com/my-url/). If the
        hub is not running in host based mode, the routespec
        *must not* have a domain component (/my-url/).

        Helpful when the hub is running in API-only mode.
        """,
    )

    @validate("extra_routes")
    def _validate_extra_routes(self, proposal):
        extra_routes = {}

        for routespec, target in proposal.value.items():
            if not isinstance(routespec, str):
                raise TraitError(
                    f"Proxy.extra_routes keys must be str, got {routespec!r}"
                )
            if not isinstance(target, str):
                raise TraitError(
                    f"Proxy.extra_routes values must be str, got {target!r}"
                )
            if not routespec.endswith("/"):

                self.log.warning(
                    f"Adding missing trailing '/' to c.Proxy.extra_routes {routespec} -> {routespec}/"
                )
                routespec += "/"

            if self.app.subdomain_host:

                if routespec.startswith("/"):
                    raise ValueError(
                        f"Proxy.extra_routes missing host component in {routespec} (must not have leading '/') when using `JupyterHub.subdomain_host = {self.app.subdomain_host!r}`"
                    )

            else:


                if not routespec.startswith("/"):
                    raise ValueError(
                        f"Proxy.extra_routes routespec {routespec} missing leading '/'."
                    )


            target_url = urlparse(target.lower())
            if target_url.scheme not in {"http", "https"} or not target_url.netloc:
                raise ValueError(
                    f"Proxy.extra_routes target {routespec}={target!r} doesn't look like a URL (should have http[s]://...)"
                )
            extra_routes[routespec] = target

        return extra_routes

    def start(self):
        ''







    def stop(self):
        ''







    def validate_routespec(self, routespec):
        ''




        if routespec == '/':


            return routespec

        host_route = not routespec.startswith('/')
        if host_route and not self.host_routing:
            raise ValueError(
                f"Cannot add host-based route {routespec!r}, not using host-routing"
            )
        if self.host_routing and not host_route:
            raise ValueError(
                f"Cannot add route without host {routespec!r}, using host-routing"
            )

        if not routespec.endswith('/'):
            return routespec + '/'
        else:
            return routespec

    async def add_route(self, routespec, target, data):
        ''

















    async def delete_route(self, routespec):
        ''




    async def get_all_routes(self):
        ''














    async def get_route(self, routespec):
        ''



















        routespec = self.validate_routespec(routespec)
        routes = await self.get_all_routes()
        return routes.get(routespec)



    async def add_service(self, service, client=None):
        ''
        if not service.server:
            raise RuntimeError(
                "Service %s does not have an http endpoint to add to the proxy.",
                service.name,
            )

        self.log.info(
            "Adding service %s to proxy %s => %s",
            service.name,
            service.proxy_spec,
            service.server.host,
        )

        await self.add_route(
            service.proxy_spec, service.server.host, {'service': service.name}
        )

    async def delete_service(self, service, client=None):
        ''
        self.log.info("Removing service %s from proxy", service.name)
        await self.delete_route(service.proxy_spec)

    async def add_user(self, user, server_name='', client=None):
        ''
        spawner = user.spawners[server_name]
        self.log.info(
            "Adding user %s to proxy %s => %s",
            user.name,
            spawner.proxy_spec,
            spawner.server.host,
        )

        if spawner.pending and spawner.pending != 'spawn':
            raise RuntimeError(
                f"{spawner._log_name} is pending {spawner.pending}, shouldn't be added to the proxy yet!"
            )

        await self.add_route(
            spawner.proxy_spec,
            spawner.server.host,
            {'user': user.name, 'server_name': server_name},
        )

    async def delete_user(self, user, server_name=''):
        ''
        routespec = user.proxy_spec
        if server_name:
            routespec = url_path_join(
                user.proxy_spec, url_escape_path(server_name), '/'
            )
        self.log.info("Removing user %s from proxy (%s)", user.name, routespec)
        await self.delete_route(routespec)

    async def add_all_services(self, service_dict):
        ''



        futures = []
        for service in service_dict.values():
            if service.server:
                futures.append(self.add_service(service))

        await asyncio.gather(*futures)

    async def add_all_users(self, user_dict):
        ''



        futures = []
        for user in user_dict.values():
            for name, spawner in user.spawners.items():
                if spawner.ready:
                    futures.append(self.add_user(user, name))

        await asyncio.gather(*futures)

    @_one_at_a_time
    async def check_routes(self, user_dict, service_dict, routes=None):
        ''
        start = time.perf_counter()
        if not routes:
            self.log.debug("Fetching routes to check")
            routes = await self.get_all_routes()

        self.log.debug("Checking routes")

        user_routes = {path for path, r in routes.items() if 'user' in r['data']}
        futures = []

        good_routes = {self.app.hub.routespec}

        hub = self.hub
        if self.app.hub.routespec not in routes:
            futures.append(self.add_hub_route(hub))
        else:
            route = routes[self.app.hub.routespec]
            if route['target'] != hub.host:
                self.log.warning(
                    "Updating Hub route %s → %s", route['target'], hub.host
                )
                futures.append(self.add_hub_route(hub))

        for user in user_dict.values():
            for name, spawner in user.spawners.items():
                if spawner.ready:
                    spec = spawner.proxy_spec
                    good_routes.add(spec)
                    if spec not in user_routes:
                        self.log.warning(
                            "Adding missing route for %s (%s)", spec, spawner.server
                        )
                        futures.append(self.add_user(user, name))
                    else:
                        route = routes[spec]
                        if route['target'] != spawner.server.host:
                            self.log.warning(
                                "Updating route for %s (%s → %s)",
                                spec,
                                route['target'],
                                spawner.server,
                            )
                            futures.append(self.add_user(user, name))
                elif spawner.pending:



                    good_routes.add(spawner.proxy_spec)


        service_routes = {
            r['data']['service']: r for r in routes.values() if 'service' in r['data']
        }
        for service in service_dict.values():
            if service.server is None:
                continue
            good_routes.add(service.proxy_spec)
            if service.name not in service_routes:
                self.log.warning(
                    "Adding missing route for %s (%s)", service.name, service.server
                )
                futures.append(self.add_service(service))
            else:
                route = service_routes[service.name]
                if route['target'] != service.server.host:
                    self.log.warning(
                        "Updating route for %s (%s → %s)",
                        route['routespec'],
                        route['target'],
                        service.server.host,
                    )
                    futures.append(self.add_service(service))


        for routespec, url in self.extra_routes.items():
            good_routes.add(routespec)
            futures.append(self.add_route(routespec, url, {'extra': True}))


        for routespec in routes:
            if routespec not in good_routes:
                self.log.warning("Deleting stale route %s", routespec)
                futures.append(self.delete_route(routespec))

        await asyncio.gather(*futures)
        stop = time.perf_counter()
        CHECK_ROUTES_DURATION_SECONDS.observe(stop - start)

    def add_hub_route(self, hub):
        ''
        self.log.info("Adding route for Hub: %s => %s", hub.routespec, hub.host)
        return self.add_route(hub.routespec, self.hub.host, {'hub': True})

    async def restore_routes(self):
        self.log.info("Setting up routes on new proxy")
        await self.add_hub_route(self.app.hub)
        await self.add_all_users(self.app.users)
        await self.add_all_services(self.app._service_map)
        self.log.info("New proxy back up and good to go")


class ConfigurableHTTPProxy(Proxy):
    ''











    proxy_process = Any()
    client = Instance(AsyncHTTPClient, ())

    concurrency = Integer(
        10,
        config=True,
        help="""
        The number of requests allowed to be concurrently outstanding to the proxy

        Limiting this number avoids potential timeout errors
        by sending too many requests to update the proxy at once
        """,
    )
    semaphore = Any()

    @default('semaphore')
    def _default_semaphore(self):
        return asyncio.BoundedSemaphore(self.concurrency)

    @observe('concurrency')
    def _concurrency_changed(self, change):
        self.semaphore = asyncio.BoundedSemaphore(change.new)


    log_level = CaselessStrEnum(
        ["debug", "info", "warn", "error"],
        "info",
        help="Proxy log level",
        config=True,
    )

    debug = Bool(False, help="Add debug-level logging to the Proxy.", config=True)

    @observe('debug')
    def _debug_changed(self, change):
        if change.new:
            self.log_level = "debug"

    auth_token = Unicode(
        help="""The Proxy auth token

        Loaded from the CONFIGPROXY_AUTH_TOKEN env variable by default.
        """
    ).tag(config=True)
    check_running_interval = Integer(
        5,
        help="Interval (in seconds) at which to check if the proxy is running.",
        config=True,
    )

    @default('auth_token')
    def _auth_token_default(self):
        token = os.environ.get('CONFIGPROXY_AUTH_TOKEN', '')
        if self.should_start and not token:

            self.log.info("Generating new CONFIGPROXY_AUTH_TOKEN")
            token = utils.new_token()
        return token

    api_url = Unicode(
        config=True, help="""The ip (or hostname) of the proxy's API endpoint"""
    )

    @default('api_url')
    def _api_url_default(self):
        url = '127.0.0.1:8001'
        proto = 'http'
        if self.app.internal_ssl:
            proto = 'https'

        return f"{proto}://{url}"

    command = Command(
        'configurable-http-proxy',
        config=True,
        help="""The command to start the proxy""",
    )

    pid_file = Unicode(
        "jupyterhub-proxy.pid",
        config=True,
        help="File in which to write the PID of the proxy process.",
    )

    _check_running_callback = Any(
        help="PeriodicCallback to check if the proxy is running"
    )

    def _check_pid(self, pid):
        if os.name == 'nt':
            import psutil

            if not psutil.pid_exists(pid):
                raise ProcessLookupError

            try:
                process = psutil.Process(pid)
                if self.command and self.command[0]:
                    process_cmd = process.cmdline()
                    if process_cmd and not any(
                        self.command[0] in clause for clause in process_cmd
                    ):
                        raise ProcessLookupError
            except (psutil.AccessDenied, psutil.NoSuchProcess):


                raise ProcessLookupError
        else:
            os.kill(pid, 0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        if not self.auth_token and not self.should_start:
            raise ValueError(
                f"{self.__class__.__name__}.auth_token or CONFIGPROXY_AUTH_TOKEN env is required"
                " if Proxy.should_start is False"
            )

    def _check_previous_process(self):
        ''
        if not self.pid_file or not os.path.exists(self.pid_file):
            return
        pid_file = os.path.abspath(self.pid_file)
        self.log.warning("Found proxy pid file: %s", pid_file)
        try:
            with open(pid_file) as f:
                pid = int(f.read().strip())
        except ValueError:
            self.log.warning("%s did not appear to contain a pid", pid_file)
            self._remove_pid_file()
            return

        try:
            self._check_pid(pid)
        except ProcessLookupError:
            self.log.warning("Proxy no longer running at pid=%s", pid)
            self._remove_pid_file()
            return


        self.log.warning("Proxy still running at pid=%s", pid)
        if os.name != 'nt':
            sig_list = [signal.SIGTERM] * 2 + [signal.SIGKILL]
        for i in range(3):
            try:
                if os.name == 'nt':
                    self._terminate_win(pid)
                else:
                    os.kill(pid, sig_list[i])
            except ProcessLookupError:
                break
            time.sleep(1)
            try:
                self._check_pid(pid)
            except ProcessLookupError:
                break

        try:
            self._check_pid(pid)
        except ProcessLookupError:
            self.log.warning("Stopped proxy at pid=%s", pid)
            self._remove_pid_file()
            return
        else:
            raise RuntimeError("Failed to stop proxy at pid=%s", pid)

    def _write_pid_file(self):
        ''
        self.log.debug("Writing proxy pid file: %s", self.pid_file)
        with open(self.pid_file, "w") as f:
            f.write(str(self.proxy_process.pid))

    def _remove_pid_file(self):
        ''
        if not self.pid_file:
            return
        self.log.debug("Removing proxy pid file %s", self.pid_file)
        try:
            os.remove(self.pid_file)
        except FileNotFoundError:
            self.log.debug("PID file %s already removed", self.pid_file)

    def _get_ssl_options(self):
        ''
        cmd = []
        proxy_api = 'proxy-api'
        proxy_client = 'proxy-client'
        api_key = self.app.internal_proxy_certs[
            proxy_api
        ][
            'keyfile'
        ]
        api_cert = self.app.internal_proxy_certs[proxy_api]['certfile']
        api_ca = self.app.internal_trust_bundles[proxy_api + '-ca']

        client_key = self.app.internal_proxy_certs[proxy_client]['keyfile']
        client_cert = self.app.internal_proxy_certs[proxy_client]['certfile']
        client_ca = self.app.internal_trust_bundles[proxy_client + '-ca']

        cmd.extend(['--api-ssl-key', api_key])
        cmd.extend(['--api-ssl-cert', api_cert])
        cmd.extend(['--api-ssl-ca', api_ca])
        cmd.extend(['--api-ssl-request-cert'])
        cmd.extend(['--api-ssl-reject-unauthorized'])

        cmd.extend(['--client-ssl-key', client_key])
        cmd.extend(['--client-ssl-cert', client_cert])
        cmd.extend(['--client-ssl-ca', client_ca])
        cmd.extend(['--client-ssl-request-cert'])
        cmd.extend(['--client-ssl-reject-unauthorized'])
        return cmd

    async def start(self):
        ''

        self._check_previous_process()


        public_server = Server.from_url(self.public_url)
        api_server = Server.from_url(self.api_url)
        env = os.environ.copy()
        env['CONFIGPROXY_AUTH_TOKEN'] = self.auth_token
        cmd = self.command + [
            '--ip',
            public_server.ip,
            '--port',
            str(public_server.port),
            '--api-ip',
            api_server.ip,
            '--api-port',
            str(api_server.port),
            '--error-target',
            url_path_join(self.hub.url, 'error'),
            '--log-level',
            self.log_level,
        ]
        if self.app.subdomain_host:
            cmd.append('--host-routing')
        if self.ssl_key:
            cmd.extend(['--ssl-key', self.ssl_key])
        if self.ssl_cert:
            cmd.extend(['--ssl-cert', self.ssl_cert])
        if self.app.internal_ssl:
            cmd.extend(self._get_ssl_options())

        if ' --ssl' not in ' '.join(cmd):
            self.log.warning(
                "Running JupyterHub without SSL."
                "  I hope there is SSL termination happening somewhere else..."
            )
        self.log.info("Starting proxy @ %s", public_server.bind_url)
        self.log.debug("Proxy cmd: %s", cmd)
        shell = os.name == 'nt'
        try:
            self.proxy_process = Popen(
                cmd, env=env, start_new_session=True, shell=shell
            )
        except FileNotFoundError as e:
            self.log.error(
                f"Failed to find proxy {self.command!r}\n"
                "The proxy can be installed with `npm install -g configurable-http-proxy`."
                "To install `npm`, install nodejs which includes `npm`."
                "If you see an `EACCES` error or permissions error, refer to the `npm` "
                "documentation on How To Prevent Permissions Errors."
            )
            raise

        self._write_pid_file()

        async def wait_for_process():
            ''








            while True:
                status = self.proxy_process.poll()
                if status is not None:
                    with self.proxy_process:
                        e = RuntimeError(
                            f"Proxy failed to start with exit code {status}"
                        )
                        raise e from None
                await asyncio.sleep(0.5)



        process_exited = asyncio.ensure_future(wait_for_process())


        server_futures = [
            asyncio.ensure_future(server.wait_up(10))
            for server in (public_server, api_server)
        ]
        servers_ready = asyncio.gather(*server_futures)



        wait_timeout = 15
        ready, pending = await asyncio.wait(
            [
                process_exited,
                servers_ready,
            ],
            return_when=asyncio.FIRST_COMPLETED,
            timeout=wait_timeout,
        )
        for task in [servers_ready, process_exited] + server_futures:

            if not task.done():
                task.cancel()
        if not ready:



            raise TimeoutError(
                f"Waiting for proxy endpoints didn't complete in {wait_timeout}s"
            )
        if process_exited in ready:

            await process_exited
        else:


            await servers_ready

        self.log.debug("Proxy started and appears to be up")
        pc = PeriodicCallback(self.check_running, 1e3 * self.check_running_interval)
        self._check_running_callback = pc
        pc.start()

    def _terminate_win(self, pid):


        import psutil

        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            child.terminate()
        gone, alive = psutil.wait_procs(children, timeout=5)
        for p in alive:
            p.kill()

        try:
            parent.terminate()
            parent.wait(timeout=5)
            parent.kill()
        except psutil.NoSuchProcess:
            pass

    def _terminate(self):
        ''
        if os.name == 'nt':
            self._terminate_win(self.proxy_process.pid)
        else:
            self.proxy_process.terminate()

    def stop(self):
        self.log.info("Cleaning up proxy[%i]...", self.proxy_process.pid)
        if self._check_running_callback is not None:
            self._check_running_callback.stop()
        if self.proxy_process.poll() is None:
            try:
                self._terminate()
            except Exception as e:
                self.log.error("Failed to terminate proxy process: %s", e)
        self._remove_pid_file()

    async def check_running(self):
        ''
        if self.proxy_process.poll() is None:
            return
        self.log.error(
            "Proxy stopped with exit code %r",
            'unknown' if self.proxy_process is None else self.proxy_process.poll(),
        )
        self._remove_pid_file()
        await self.start()
        await self.restore_routes()

    def _routespec_to_chp_path(self, routespec):
        ''



        path = self.validate_routespec(routespec)

        if not path.startswith('/'):
            path = '/' + path

        if path != '/' and path.endswith('/'):
            path = path.rstrip('/')
        return path

    def _routespec_from_chp_path(self, chp_path):
        ''






        routespec = quote(chp_path, safe='@/~')
        if self.host_routing:

            routespec = routespec.lstrip('/')

        if not routespec.endswith('/'):
            routespec = routespec + '/'
        return routespec

    async def api_request(self, path, method='GET', body=None, client=None):
        ''
        client = client or AsyncHTTPClient()
        url = url_path_join(self.api_url, 'api/routes', path)

        if isinstance(body, dict):
            body = json.dumps(body)
        self.log.debug("Proxy: Fetching %s %s", method, url)
        req = HTTPRequest(
            url,
            method=method,
            headers={'Authorization': f'token {self.auth_token}'},
            body=body,
            connect_timeout=3,
            request_timeout=10,
        )

        async def _wait_for_api_request():
            try:
                async with self.semaphore:
                    return await client.fetch(req)
            except HTTPError as e:



                if e.code >= 500:
                    self.log.warning(
                        f"api_request to the proxy failed with status code {e.code}, retrying..."
                    )
                    return False
                else:
                    self.log.error(f"api_request to proxy failed: {e}")

                    raise

        result = await exponential_backoff(
            _wait_for_api_request,
            f'Repeated api_request to proxy path "{path}" failed.',
            timeout=30,
        )
        return result

    async def add_route(self, routespec, target, data):
        body = data or {}
        body['target'] = target
        body['jupyterhub'] = True
        path = self._routespec_to_chp_path(routespec)
        await self.api_request(path, method='POST', body=body)

    async def delete_route(self, routespec):
        path = self._routespec_to_chp_path(routespec)
        try:
            await self.api_request(path, method='DELETE')
        except HTTPError as e:
            if e.code == 404:



                self.log.warning("Route %s already deleted", routespec)
            else:
                raise

    def _reformat_routespec(self, routespec, chp_data):
        ''
        target = chp_data.pop('target')
        chp_data.pop('jupyterhub')
        return {'routespec': routespec, 'target': target, 'data': chp_data}

    async def get_all_routes(self, client=None):
        ''
        proxy_poll_start_time = time.perf_counter()
        resp = await self.api_request('', client=client)
        chp_routes = json.loads(resp.body.decode('utf8', 'replace'))
        all_routes = {}
        for chp_path, chp_data in chp_routes.items():
            routespec = self._routespec_from_chp_path(chp_path)
            if 'jupyterhub' not in chp_data:

                self.log.debug("Omitting non-jupyterhub route %r", routespec)
                continue
            all_routes[routespec] = self._reformat_routespec(routespec, chp_data)
        PROXY_POLL_DURATION_SECONDS.observe(time.perf_counter() - proxy_poll_start_time)
        return all_routes
