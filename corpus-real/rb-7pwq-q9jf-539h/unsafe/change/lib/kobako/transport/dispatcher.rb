

require_relative "../codec"
require_relative "request"
require_relative "response"
require_relative "yield"
require_relative "yielder"

module Kobako



  module Transport
















    module Dispatcher



      BREAK_THROW = :__kobako_break__
      private_constant :BREAK_THROW

      module_function





      class UndefinedTargetError < StandardError; end














      def dispatch(request_bytes, namespaces, handler, yield_to_guest)
        request = Kobako::Transport::Request.decode(request_bytes)
        target = resolve_target(request.target, namespaces, handler)
        args, kwargs = resolve_call_args(request, handler)
        yielder = Yielder.new(yield_to_guest, BREAK_THROW, handler) if request.block_given
        value = catch(BREAK_THROW) { invoke(target, request.method_name, args, kwargs, yielder) }
        encode_ok(value, handler)
      rescue StandardError => e
        encode_caught_error(e)
      ensure
        yielder&.invalidate!
      end





      def resolve_call_args(request, handler)
        args = request.args.map { |v| resolve_arg(v, handler) }
        kwargs = request.kwargs.transform_values { |v| resolve_arg(v, handler) }
        [args, kwargs]
      end









      def encode_caught_error(error)
        case error
        when Kobako::Codec::Error then encode_error("runtime",
                                                    "Sandbox received a malformed request: #{error.message}")
        when UndefinedTargetError then encode_error("undefined", error.message)
        when ArgumentError        then encode_error("argument", error.message)
        else                           encode_error("runtime", "#{error.class}: #{error.message}")
        end
      end













      def invoke(target, method, args, kwargs, yielder = nil)
        block = yielder&.to_proc
        if kwargs.empty?
          target.public_send(method.to_sym, *args, &block)
        else
          target.public_send(method.to_sym, *args, **kwargs, &block)
        end
      end





      def resolve_arg(value, handler)
        case value
        when Kobako::Handle
          require_live_object!(value.id, handler)
        else
          value
        end
      end








      def resolve_target(target, namespaces, handler)
        case target
        when String
          resolve_path(target, namespaces)
        when Kobako::Handle
          resolve_handle(target, handler)
        end
      end

      def resolve_path(path, namespaces)
        namespaces.lookup(path)
      rescue KeyError => e
        raise UndefinedTargetError, e.message
      end

      def resolve_handle(handle, handler)
        require_live_object!(handle.id, handler)
      end



      def require_live_object!(id, handler)
        handler.fetch(id)
      rescue Kobako::SandboxError => e
        raise UndefinedTargetError, e.message
      end







      def encode_ok(value, handler)
        response = Kobako::Transport::Response.ok(value)
        response.encode
      rescue Kobako::Codec::UnsupportedType
        encode_ok(wrap_as_handle(value, handler), handler)
      end





      def wrap_as_handle(value, handler)
        handler.alloc(value)
      end

      def encode_error(type, message)
        fault = Kobako::Fault.new(type: type, message: message)
        response = Kobako::Transport::Response.error(fault)
        response.encode
      end
    end
  end
end
