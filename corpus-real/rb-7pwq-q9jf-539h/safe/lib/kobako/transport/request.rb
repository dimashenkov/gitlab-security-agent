

require_relative "../handle"
require_relative "../codec"

module Kobako



  module Transport



    STATUS_OK    = 0

    STATUS_ERROR = 1
















    class Request < Data.define(:target, :method_name, :args, :kwargs, :block_given)
      def initialize(target:, method_name:, args: [], kwargs: {}, block_given: false)
        unless target.is_a?(String) || target.is_a?(Kobako::Handle)
          raise ArgumentError, "Request target must be String or Kobako::Handle, got #{target.class}"
        end
        raise ArgumentError, "Request method_name must be String" unless method_name.is_a?(String)
        raise ArgumentError, "Request args must be Array"         unless args.is_a?(Array)
        unless block_given.is_a?(TrueClass) || block_given.is_a?(FalseClass)
          raise ArgumentError, "Request block_given must be Boolean, got #{block_given.class}"
        end

        validate_kwargs!(kwargs)
        super
      end



      def encode
        Codec::Encoder.encode([target, method_name, args, kwargs, block_given])
      end




      def self.decode(bytes)
        Codec::Decoder.decode(bytes) do |arr|
          unless arr.is_a?(Array) && arr.length == 5
            raise Codec::InvalidType, "Request envelope is malformed (expected a 5-element array)"
          end

          target, method_name, args, kwargs, block_given = arr
          new(target: target, method_name: method_name, args: args, kwargs: kwargs, block_given: block_given)
        end
      end

      private

      def validate_kwargs!(kwargs)
        raise ArgumentError, "Request kwargs must be Hash" unless kwargs.is_a?(Hash)

        kwargs.each_key do |k|
          raise ArgumentError, "Request kwargs keys must be Symbol, got #{k.class}" unless k.is_a?(Symbol)
        end
      end
    end
  end
end
