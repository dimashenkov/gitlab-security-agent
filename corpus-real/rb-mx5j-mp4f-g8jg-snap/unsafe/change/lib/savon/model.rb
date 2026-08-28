

module Savon
  module Model
    def self.extended(base)
      base.setup
    end

    def setup
      class_operation_module
      instance_operation_module
    end



    def operations(*operations)
      operations.each do |operation|
        define_class_operation(operation)
        define_instance_operation(operation)
      end
    end

    def all_operations
      operations(*client.operations)
    end

    private


    def define_class_operation(operation)
      class_operation_module.module_eval %{
        def #{StringUtils.snakecase(operation.to_s)}(locals = {})
          client.call #{operation.inspect}, locals
        end
      }, __FILE__, __LINE__ - 4
    end


    def define_instance_operation(operation)
      instance_operation_module.module_eval %{
        def #{StringUtils.snakecase(operation.to_s)}(locals = {})
          self.class.#{StringUtils.snakecase(operation.to_s)} locals
        end
      }, __FILE__, __LINE__ - 4
    end


    def class_operation_module
      @class_operation_module ||= Module.new do
        def client(globals = {})
          @client ||= Savon::Client.new(globals)
        rescue InitializationError
          raise_initialization_error!
        end

        def global(option, *value)
          client.globals[option] = value
        end

        def raise_initialization_error!
          raise InitializationError,
                "Expected the model to be initialized with either a WSDL document or the SOAP endpoint and target namespace options.\n" \
                "Make sure to setup the model by calling the .client class method before calling the .global method.\n\n" \
                "client(wsdl: '/Users/me/project/service.wsdl')                              # to use a local WSDL document\n" \
                "client(wsdl: 'http://example.com?wsdl')                                     # to use a remote WSDL document\n" \
                "client(endpoint: 'http://example.com', namespace: 'http://v1.example.com')  # if you don't have a WSDL document"
        end
      end.tap { |mod| extend(mod) }
    end


    def instance_operation_module
      @instance_operation_module ||= Module.new do
        def client
          self.class.client
        end
      end.tap { |mod| include(mod) }
    end
  end
end
