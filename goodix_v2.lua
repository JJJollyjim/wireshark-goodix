protocol = Proto("goodix2",  "Goodix Fingerprint Sensor v2 Protocol")

type = ProtoField.uint8("goodix2.type", "type", base.HEX)
len = ProtoField.uint16("goodix2.len", "len", base.DEC)
cksum = ProtoField.uint8("goodix2.cksum", "cksum", base.HEX)

protocol.fields = { type, len, cksum }

function get_type_name(type)
   if type == 0xa0 then
      return "Plaintext Message"
   elseif type == 0xb0 then
      return "TLS Packet"
   end
   return "Unknown"
end

function protocol.dissector(buffer, pinfo, tree)
   length = buffer:len()
   if length == 0 then return end

   pinfo.cols.protocol = "GoodixV2"

   local subtree = tree:add(protocol, buffer(0,4), "Goodix v2 Enscapsulation")

   type_val = buffer(0,1):le_uint()

   subtree:add_le(type, buffer(0,1)):append_text(" (" .. get_type_name(type_val) .. ")")
   subtree:add_le(len, buffer(1,2))
   subtree:add_le(cksum, buffer(3,1))

   if type_val == 0xa0 then
      Dissector.get("goodix"):call(buffer(4):tvb(), pinfo, tree)
   elseif type_val == 0xb0 then
      Dissector.get("tls"):call(buffer(4):tvb(), pinfo, tree)
   end
end

DissectorTable.get("udp.port"):add(1, protocol)
