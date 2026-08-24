

require_relative "../codec"
require_relative "yield"

module Kobako



  module Transport























    class Yielder








      def initialize(yield_to_guest, break_tag, handler)
        @yield_to_guest = yield_to_guest
        @break_tag = break_tag
        @handler = handler
        @active = true
      end








      def yield(*args)
        raise LocalJumpError, "guest block invoked after host dispatch frame returned" unless @active

        response = Kobako::Transport::Yield.decode(@yield_to_guest.call(Kobako::Codec::Encoder.encode(args)))
        return restore(response.value) if response.ok?

        throw @break_tag, response.value if response.break?

        raise yield_failure(response.value, default: "yield error")
      end



      def to_proc
        method(:yield).to_proc
      end




      def invalidate!
        @active = false
      end

      private








      def restore(value)
        Kobako::Codec::Utils.deep_restore(value, @handler)
      end






      def yield_failure(payload, default:)
        return RuntimeError.new(default) unless payload.is_a?(Hash)

        klass = payload["class"] || "RuntimeError"
        message = payload["message"] || default
        RuntimeError.new("#{klass}: #{message}")
      end
    end
  end
end
