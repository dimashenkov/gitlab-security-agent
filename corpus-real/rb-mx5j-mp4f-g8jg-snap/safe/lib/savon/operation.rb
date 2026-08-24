

require "savon/options"
require "savon/block_interface"
require "savon/builder"
require "savon/response"
require "savon/http_error"
require "savon/transport/httpi"
require "savon/transport/faraday"
require "mail"

module Savon





  class Operation


    CONTENT_TYPE = {
      1 => "text/xml;charset=%s",
      2 => "application/soap+xml;charset=%s"
    }.freeze



    SOAP_REQUEST_TYPE = {
      1 => "text/xml",
      2 => "application/soap+xml"
    }.freeze

    def self.create(operation_name, wsdl, globals, transport)
      if wsdl.document?
        ensure_name_is_symbol! operation_name
        ensure_exists! operation_name, wsdl
      end

      new(operation_name, wsdl, globals, transport)
    end

    def self.ensure_exists!(operation_name, wsdl)
      unless wsdl.soap_actions.include? operation_name
        raise UnknownOperationError, "Unable to find SOAP operation: #{operation_name.inspect}\n" \
                                     "Operations provided by your service: #{wsdl.soap_actions.inspect}"
      end
    rescue Wasabi::Resolver::HTTPError => e
      raise HTTPError, e.response
    end

    def self.ensure_name_is_symbol!(operation_name)
      return if operation_name.is_a? Symbol

      raise ArgumentError, "Expected the first parameter (the name of the operation to call) to be a symbol\n" \
                           "Actual: #{operation_name.inspect} (#{operation_name.class})"
    end

    def initialize(name, wsdl, globals, transport)
      @name      = name
      @wsdl      = wsdl
      @globals   = globals
      @transport = transport
    end

    def build(locals = {}, &block)
      set_locals(locals, block)
      Builder.new(@name, @wsdl, @globals, @locals)
    end






    def call(locals = {}, &block)
      builder  = build(locals, &block)
      response = Savon.notify_observers(@name, builder, @globals, @locals)

      response =
        if response.nil?
          body = builder.to_s
          headers = soap_headers(builder)
          @transport.post(endpoint.to_s, headers, body, @locals)
        else
          normalize_observer_response(response)
        end

      create_response(response)
    end




    def request(locals = {}, &block)
      if @globals[:transport] == :faraday
        raise ArgumentError, "#request returns an HTTPI::Request and is not supported " \
                             "with transport: :faraday. Use client.faraday to configure " \
                             "the connection"
      end

      builder = build(locals, &block)

      body = builder.to_s
      @transport.to_httpi_request(endpoint.to_s, soap_headers(builder), body, @locals)
    end

    private

    def create_response(response)
      Response.new(response, @globals, @locals)
    end

    def set_locals(locals, block)
      locals = LocalOptions.new(locals)
      BlockInterface.new(locals).evaluate(block) if block

      @locals = locals
    end







    def soap_headers(builder)
      headers = {}

      if builder.multipart

        headers["Content-Type"] = [
          "multipart/related",
          "type=\"#{SOAP_REQUEST_TYPE[@globals[:soap_version]]}\"",
          "start=\"#{builder.multipart[:start]}\"",
          "boundary=\"#{builder.multipart[:multipart_boundary]}\""
        ].join("; ")
        headers["MIME-Version"] = "1.0"
        headers["Accept-Encoding"] = "gzip,deflate"
      else
        headers["Content-Type"] = CONTENT_TYPE[@globals[:soap_version]] % @globals[:encoding]
      end

      action = soap_action
      headers["SOAPAction"] = %("#{action}") if action

      headers
    end

    def soap_action

      return if @locals.include?(:soap_action) && !@locals[:soap_action]


      @locals[:soap_action] ||

        @wsdl.document? && @wsdl.soap_action(@name.to_sym) ||

        Gyoku.xml_tag(@name, key_converter: @globals[:convert_request_keys_to])
    end

    def endpoint
      @globals[:endpoint] || @wsdl.endpoint.tap do |url|
        if @globals[:host]
          host_url = URI.parse(@globals[:host])
          url.host = host_url.host
          url.port = host_url.port
        end
      end
    end






    def normalize_observer_response(response)
      return response if response.is_a?(Transport::Response)

      if response.is_a?(HTTPI::Response)
        warn "Observers returning HTTPI::Response is deprecated - return Savon::Transport::Response instead.", uplevel: 1
        return Transport::Response.new(
          response.code,
          response.headers,
          response.body,
          cookies: HTTPI::Cookie.list_from_headers(response.headers)
        )
      end

      raise Error, "Observers need to return a Savon::Transport::Response " \
                   "to mock the request or nil to execute the request."
    end
  end
end
