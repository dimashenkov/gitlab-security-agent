

require_relative "../codec"

module Kobako



  module Transport


    TAG_OK = 0x01

    TAG_BREAK = 0x02


    TAG_RESERVED = 0x03


    TAG_ERROR = 0x04


    LIVE_TAGS = [TAG_OK, TAG_BREAK, TAG_ERROR].freeze

















    class Yield < Data.define(:tag, :value)
      def initialize(tag:, value:)
        unless Kobako::Transport::LIVE_TAGS.include?(tag)
          raise ArgumentError,
                "Yield tag must be one of #{Kobako::Transport::LIVE_TAGS.inspect}, got #{tag.inspect}"
        end

        super
      end

      def ok?    = tag == Kobako::Transport::TAG_OK
      def break? = tag == Kobako::Transport::TAG_BREAK
      def error? = tag == Kobako::Transport::TAG_ERROR



      def encode
        [tag].pack("C") + Codec::Encoder.encode(value)
      end





      def self.decode(bytes)
        bytes = bytes.b
        raise Codec::InvalidType, "YieldResponse must carry at least one byte" if bytes.empty?

        tag = bytes.getbyte(0)
        body = bytes.byteslice(1, bytes.bytesize - 1) || +""

        reject_dead_tag!(tag)
        new(tag: tag, value: Codec::Decoder.decode(body))
      end

      def self.reject_dead_tag!(tag)
        return if LIVE_TAGS.include?(tag)

        msg = if tag == TAG_RESERVED
                "YieldResponse tag 0x03 is reserved"
              else
                format(
                  "YieldResponse tag 0x%02x is not recognised", tag
                )
              end
        raise Codec::InvalidType, msg
      end
      private_class_method :reject_dead_tag!
    end
  end
end
