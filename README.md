# go-dnstap-generator

A tool for generating random dnstap messages, designed specifically for testing purposes.

Command:

To run the generator, use the following command:

```
./go-dnstap-generator -c 2 -n 1000000 -i 127.0.0.1
```

Here are the available options you can use:

```
Usage of go-dnstap-generator:
  -c int
        number of connection (default 1)
  -dmax int
        maximum domain length (default 60)
  -dmin int
        minimum domain length (default 10)
  -i string
        remote address of the dnstap receiver (default "127.0.0.1")
  -n int
        number of dnstap message to send (default 1)
  -noqueries
        don't send dnstap queries
  -noreplies
        don't send dnstap replies
  -p int
        remote port of the dnstap receiver (default 6000)
  -qname string
        specific qname to use
  -qtype string
        specific qtype to use (A, AAAA, CNAME, TXT)
  -qrtype string
        type of query and response (CLIENT, FORWARDER, RESOLVER, AUTH)
  -t string
        transport to use (default "tcp"), expected values: tcp, unix
```
