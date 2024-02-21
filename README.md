ZeroTier-QUIC - Customized ZeroTierOne Implementation with QUIC Transport Layer
======

Source Bases: 
 - [ZeroTier - A Smart Ethernet Switch for Earth](https://github.com/zerotier/ZeroTierOne)
 - [MsQuic - Cross-platform, C implementation of the IETF QUIC protocol, exposed to C, C++, C# and Rust](https://github.com/microsoft/msquic)

How To Use:
 1. Build MsQuic and make install
 2. Clone this Github repo and make
 3. Run zerotier-one binary with -m and -n to use QUIC+TLS transport and disable original transport crypto
