# wireshark-goodix

Wireshark protocol dissector for the SPI protocol of the GXFP5187.

Expects fake UDP packets on Port 1, since I don't think pcap has a SPI linktype.

`goodix_message.lua` describes the interesting packet information.
`goodix_v2.lua` is an encapsulation format that specifies whether or not the
packet is encrypted with TLS. Decrypted data is then fed back in to the
goodix_message dissector.

Sample data is available in sample_data.pcap (though the timestamps are incorrect)

### Usage

Drop both .lua files in `~/.local/lib/wireshark/plugins` (or another 
[plugin directory](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html))

### Decryption

Enter your 48-byte PSK (as 96 bytes of hex) in Edit -> Preferences -> Protocols
-> TLS -> Pre-Shared-Key

Wireshark may complain in the TLS Application Data packet dissection that the
packet length exceeds the maximum from the spec -- this appears to not matter,
the data all decrypts correctly anyway.
