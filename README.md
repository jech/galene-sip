# Galene-sip: SIP gateway for the Galene videoconferencing server

Galene-SIP is a work in progress gateway between the Galene
videoconferencing server and the SIP protocol.  It currently has the
following features:

  * register with a SIP registrar;
  * receive SIP calls and bridge them to Galene;
  * recode audio from SIP to Galene;
  * decode, mix and reencode audio from Galene to SIP;
  * silence detection.
  
This is a work in progress, and the following features are required before
this can be used in production:

  * NAT support (keepalives, STUN, etc.);
  * SIP over TCP and SIP over TLS;
  * client offers (we currently assume that the server will send the offer);
  * support for Opus on the SIP side (only PCMU and PCMA (G.711) are supported,
    Opus is of course supported on the Galene side);
  * more complete RTCP on the SIP side;
  * unit tests.


## Building

Galene-SIP requires the `libopus` library.  On Debian-based systems,
please do:
```sh
apt install libopus-dev
```

Then do:
```
go build
```

## Usage

Your SIP provider has provided you with four items of data:

  * your SIP address, for example `sip:user@sip.example.com`;
  * your SIP password, for example `1234`;
  * the SIP registrar to use, for example `sip.example.com`;
  * the SIP proxy address to use, for example `sip.example.com`.
  
The registrar and proxy addresses are usually (but not always) equal to
the domain name in the SIP address.
  
Your Galene administrator has provided you either with a Galene invite, of
the form

  * https://galene.example.org:8443/group/conference/?token=XXXX
  
or a Galene URL without a token together with a username and password.

In the common case, it is enough to run
```sh
./galene-sip -sip sip:user@sip.example.com -sip-password 1234 \
             https://galene.example.org:8443/group/conference/?token=XXXX
```

You may use the option `-sip-registrar` if the registrar is different than
the domain part of your SIP address.  You may use the options `-username`
and `-password` if your Galene URL does not contain a token.  Please type
```sh
./galene-sip -help
```
for more information.

Now call your SIP address, and your call should be bridged to the Galene group.
If something goes wrong, run with the option `-debug` and send me the log.


— Juliusz Chroboczek

