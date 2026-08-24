

require_relative "../codec"
require_relative "../fault"
require_relative "request"

module Kobako


  module Transport










    class Response < Data.define(:status, :payload)
      def self.ok(value)
        new(status: STATUS_OK, payload: value)
      end

      def self.error(fault)
        unless fault.is_a?(Kobako::Fault)
          raise ArgumentError, "Response.error requires Kobako::Fault, got #{fault.class}"
        end

        new(status: STATUS_ERROR, payload: fault)
      end




      def self.decode(bytes)
        Codec::Decoder.decode(bytes) do |arr|
          unless arr.is_a?(Array) && arr.length == 2
            raise Codec::InvalidType, "Response envelope is malformed (expected a 2-element array)"
          end

          status, payload = arr
          new(status: status, payload: payload)
        end
      end

      def initialize(status:, payload:)
        unless [STATUS_OK, STATUS_ERROR].include?(status)
          raise ArgumentError, "Response status must be 0 (ok) or 1 (error), got #{status.inspect}"
        end
        if status == STATUS_ERROR && !payload.is_a?(Kobako::Fault)
          raise ArgumentError, "Response with error status must carry a Kobako::Fault payload"
        end

        super
      end

      def ok?    = status == STATUS_OK
      def error? = status == STATUS_ERROR



      def encode
        Codec::Encoder.encode([status, payload])
      end
    end
  end
end
