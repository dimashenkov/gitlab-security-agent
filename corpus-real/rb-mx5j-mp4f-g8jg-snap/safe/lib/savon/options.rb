

require "logger"
require "httpi"
require "savon/faraday_migration_hint"

module Savon



  class Options
    def initialize(options = {})
      @options = {}
      assign options
    end

    attr_reader :option_type

    def [](option)
      @options[option]
    end

    def []=(option, value)
      value = [value].flatten
      send(option, *value)
    end

    def include?(option)
      @options.key? option
    end

    private

    def assign(options)
      options.each do |option, value|
        send(option, value)
      end
    end

    def method_missing(option, _)
      raise UnknownOptionError, "Unknown #{option_type} option: #{option.inspect}"
    end
  end



  module SharedOptions





    def wsse_auth(*credentials)
      credentials.flatten!
      @options[:wsse_auth] =
        if credentials.size == 1
          credentials.first
        else
          credentials
        end
    end






    def wsse_timestamp(timestamp = true)
      @options[:wsse_timestamp] = timestamp
    end

    def wsse_signature(signature)
      @options[:wsse_signature] = signature
    end
  end






  module HTTPITransportOptions
    TRANSPORT_DEFAULTS = {
      adapter: nil,
      follow_redirects: false
    }.freeze



    FARADAY_INCOMPATIBLE_GLOBALS = FaradayMigrationHint::OPTIONS




    def validate_transport!
      return unless self[:transport] == :faraday

      unless faraday_loaded?
        raise InitializationError,
              "transport: :faraday requires the faraday gem.\n" \
              "Add to your Gemfile: gem 'faraday'"
      end

      violations = FARADAY_INCOMPATIBLE_GLOBALS.filter_map { |option|
        next unless include?(option)
        next if default_transport_option?(option)

        FaradayMigrationHint.new(option, self[option]).message
      }

      return if violations.empty?

      raise InitializationError,
            "The following options are not supported with transport: :faraday:\n#{violations.join("\n")}"
    end


    def proxy(proxy)
      @options[:proxy] = proxy unless proxy.nil?
    end


    def open_timeout(open_timeout)
      @options[:open_timeout] = open_timeout
    end


    def read_timeout(read_timeout)
      @options[:read_timeout] = read_timeout
    end


    def write_timeout(write_timeout)
      @options[:write_timeout] = write_timeout
    end


    def ssl_version(version)
      @options[:ssl_version] = version
    end


    def ssl_min_version(version)
      @options[:ssl_min_version] = version
    end


    def ssl_max_version(version)
      @options[:ssl_max_version] = version
    end


    def ssl_verify_mode(verify_mode)
      @options[:ssl_verify_mode] = verify_mode
    end


    def ssl_cert_key_file(file)
      @options[:ssl_cert_key_file] = file
    end


    def ssl_cert_key(key)
      @options[:ssl_cert_key] = key
    end


    def ssl_cert_key_password(password)
      @options[:ssl_cert_key_password] = password
    end


    def ssl_cert_file(file)
      @options[:ssl_cert_file] = file
    end


    def ssl_cert(cert)
      @options[:ssl_cert] = cert
    end


    def ssl_ca_cert_file(file)
      @options[:ssl_ca_cert_file] = file
    end


    def ssl_ca_cert(cert)
      @options[:ssl_ca_cert] = cert
    end


    def ssl_ciphers(ciphers)
      @options[:ssl_ciphers] = ciphers
    end


    def ssl_ca_cert_path(path)
      @options[:ssl_ca_cert_path] = path
    end


    def ssl_cert_store(store)
      @options[:ssl_cert_store] = store
    end


    def basic_auth(*credentials)
      @options[:basic_auth] = credentials.flatten
    end


    def digest_auth(*credentials)
      @options[:digest_auth] = credentials.flatten
    end


    def ntlm(*credentials)
      @options[:ntlm] = credentials.flatten
    end


    def follow_redirects(follow_redirects)
      @options[:follow_redirects] = follow_redirects
    end


    def adapter(adapter)
      @options[:adapter] = adapter
    end

    private

    def default_transport_option?(option)
      TRANSPORT_DEFAULTS.key?(option) && self[option] == TRANSPORT_DEFAULTS[option]
    end


    def faraday_loaded?
      require "faraday"
      true
    rescue LoadError
      false
    end
  end





  class GlobalOptions < Options
    include SharedOptions
    include HTTPITransportOptions

    def initialize(options = {})
      @option_type = :global
      options = defaults.merge(options)



      delayed_level = options.delete(:log_level)

      super(options)

      log_level(delayed_level) unless delayed_level.nil?
    end


    def wsdl(wsdl_address)
      @options[:wsdl] = wsdl_address
    end


    def host(host)
      @options[:host] = host
    end


    def endpoint(endpoint)
      @options[:endpoint] = endpoint
    end


    def namespace(namespace)
      @options[:namespace] = namespace
    end


    def namespace_identifier(identifier)
      @options[:namespace_identifier] = identifier
    end


    def namespaces(namespaces)
      @options[:namespaces] = namespaces
    end


    def headers(headers)
      @options[:headers] = headers
    end


    def encoding(encoding)
      @options[:encoding] = encoding
    end


    def soap_header(header)
      @options[:soap_header] = header
    end




    def element_form_default(element_form_default)
      @options[:element_form_default] = element_form_default
    end




    def env_namespace(env_namespace)
      @options[:env_namespace] = env_namespace
    end


    def soap_version(soap_version)
      @options[:soap_version] = soap_version
    end


    def raise_errors(raise_errors)
      @options[:raise_errors] = raise_errors
    end


    def log(log)
      HTTPI.log = log
      @options[:log] = log
    end


    def logger(logger)
      HTTPI.logger = logger
      @options[:logger] = logger
    end


    def log_level(level)
      levels = { debug: 0, info: 1, warn: 2, error: 3, fatal: 4 }

      unless levels.include? level
        raise ArgumentError, "Invalid log level: #{level.inspect}\n" \
                             "Expected one of: #{levels.keys.inspect}"
      end

      @options[:logger].level = levels[level]
    end


    def log_headers(log_headers)
      @options[:log_headers] = log_headers
    end


    def filters(*filters)
      @options[:filters] = filters.flatten
    end


    def pretty_print_xml(pretty_print_xml)
      @options[:pretty_print_xml] = pretty_print_xml
    end


    def strip_namespaces(strip_namespaces)
      @options[:strip_namespaces] = strip_namespaces
    end


    def delete_namespace_attributes(delete_namespace_attributes)
      @options[:delete_namespace_attributes] = delete_namespace_attributes
    end




    def empty_tag_value(value)
      @options[:empty_tag_value] = value
    end



    def convert_dashes_to_underscores(convert)
      @options[:convert_dashes_to_underscores] = convert
    end




    def scrub_xml(scrub)
      @options[:scrub_xml] = scrub
    end



    def convert_request_keys_to(converter)
      @options[:convert_request_keys_to] = converter
    end



    def unwrap(unwrap)
      @options[:unwrap] = unwrap
    end




    def convert_response_tags_to(converter = nil, &block)
      @options[:convert_response_tags_to] = block || converter
    end




    def convert_attributes_to(converter = nil, &block)
      @options[:convert_attributes_to] = block || converter
    end


    def multipart(multipart)
      if multipart
        warn "The global :multipart option has been a no-op since v2.13.0. " \
          "Savon detects whether the response is multipart by checking if the " \
          "response Content-Type header contains 'multipart'. You can remove" \
          "this option from your code to make this warning disappear.", uplevel: 1
      end
      @options[:multipart] = multipart
    end


    def use_wsa_headers(use)
      @options[:use_wsa_headers] = use
    end


    def no_message_tag(bool)
      @options[:no_message_tag] = bool
    end




    def transport(transport)
      @options[:transport] = transport
    end

    private


    def defaults
      HTTPITransportOptions::TRANSPORT_DEFAULTS.merge(
        encoding: "UTF-8",
        soap_version: 1,
        namespaces: {},
        logger: Logger.new($stdout),
        log: false,
        log_headers: true,
        filters: [],
        pretty_print_xml: false,
        raise_errors: true,
        strip_namespaces: true,
        delete_namespace_attributes: false,
        empty_tag_value: nil,
        convert_dashes_to_underscores: true,
        scrub_xml: true,
        convert_response_tags_to: ->(tag) { StringUtils.snakecase(tag).to_sym },
        convert_attributes_to: ->(k, v) { [k, v] },
        multipart: false,
        use_wsa_headers: false,
        no_message_tag: false,
        unwrap: false,
        host: nil,
        transport: :httpi
      )
    end
  end



  class LocalOptions < Options
    include SharedOptions

    def initialize(options = {})
      @option_type = :local

      defaults = {
        advanced_typecasting: true,
        response_parser: :nokogiri,
        multipart: false
      }

      super defaults.merge(options)
    end




    def soap_header(header)
      @options[:soap_header] = header
    end


    def message(message)
      @options[:message] = message
    end



    def message_tag(message_tag)
      @options[:message_tag] = message_tag
    end


    def attributes(attributes)
      @options[:attributes] = attributes
    end































    def attachments(attachments)
      @options[:attachments] = attachments
    end


    def soap_action(soap_action)
      @options[:soap_action] = soap_action
    end


    def cookies(cookies)
      @options[:cookies] = cookies
    end


    def xml(xml)
      @options[:xml] = xml
    end


    def advanced_typecasting(advanced)
      @options[:advanced_typecasting] = advanced
    end


    def response_parser(parser)
      @options[:response_parser] = parser
    end


    def multipart(multipart)
      if multipart
        warn "The local :multipart option has been a no-op since v2.13.0. " \
            "Savon detects whether the response is multipart by checking if the " \
            "response Content-Type header contains 'multipart'. You can remove" \
            "this option from your code to make this warning disappear.", uplevel: 1
      end
      @options[:multipart] = multipart
    end


    def headers(headers)
      @options[:headers] = headers
    end
  end
end
