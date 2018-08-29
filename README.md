# Echo and Log

## Description
This is a small Python3 script that listens on TCP ports, echoes received data back to the sender, and logs connections and data.

The purpose is to characterize the data sent to arbitrary ports, enabling users to quickly determine what protocols they're seeing to ports on their honeypot.  Defenders could then place more relevant software listening on those ports to improve honeypot interactions.

## Usage
```sh
sudo ./echo\_and\_log.py -p "15,20,30,55"
```

Sudo is not necessary if you're using unprivileged ports, or have set capabilities correctly.  Echo\_and\_log's first steps, though, are to begin listening and drop root privileges, hopefully mitigating most problems with running as root.

# Requires
python-logstash
