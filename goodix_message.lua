protocol = Proto("goodix",  "Goodix Fingerprint Sensor Message Protocol")

cmd1 = ProtoField.uint8("goodix.cmd1", "cmd1", base.HEX, nil, 0xF0)
cmd2 = ProtoField.uint8("goodix.cmd2", "cmd2", base.HEX, nil, 0x0E)
len = ProtoField.uint16("goodix.len", "len", base.DEC)
cksum = ProtoField.uint8("goodix.cksum", "cksum", base.HEX)
body = ProtoField.none("goodix.body", "body")

protocol.fields = { cmd1, cmd2, len, cksum, body }

-- From log file, used as a fallback when the full cmd name is unknown
cmd1_names = {
   [0x0] = "NOP",
   [0x2] = "Ima",
   [0x3] = "FDT",
   [0x4] = "FF",
   [0x5] = "NAV",
   [0x6] = "Sle",
   [0x7] = "IDL",
   [0x8] = "REG",
   [0x9] = "CHIP",
   [0xA] = "OTHER",
   [0xB] = "MSG",
   [0xC] = "NOTI",
   [0xD] = "TLSCONN",
   [0xE] = "PROD",
   [0xF] = "UPFW",
}

cmd_names = {
   [0x20] = "Image Data",
   [0xA8] = "Get Firmware Version",
   [0xB0] = "Ack",
}

function protocol.dissector(buffer, pinfo, tree)
   length = buffer:len()
   if length == 0 then return end

   pinfo.cols.protocol = "Goodix"

   local subtree = tree:add(protocol, buffer(), "Goodix Message Protocol")

   cmd_val = buffer(0, 1):le_uint()
   if cmd_names[cmd_val] ~= nil then
      pinfo.cols.info = cmd_names[cmd_val]
   else
      pinfo.cols.info = string.format("Unknown command (%7s.%x)", cmd1_names[bit.rshift(cmd_val, 4)], bit.rshift(cmd_val%16, 1))
   end

   subtree:add_le(cmd1, buffer(0,1))
   subtree:add_le(cmd2, buffer(0,1))
   subtree:add_le(len, buffer(1,2))
   subtree:add_le(body, buffer(3,buffer:len()-4))
   subtree:add_le(cksum, buffer(buffer:len()-1,1))
end

DissectorTable.get("tls.port"):add(1, protocol)
