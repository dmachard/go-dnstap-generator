# go-dnstap-generator

Dnstap random generator for testing purpose only.

Command:

```
./go-dnstap-generator -c 2 -n 1000000 -i 127.0.0.1
```

Options:

```
  -c int
        number of connection (default 1)
  -d int
        domain length (default 60)
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
```
