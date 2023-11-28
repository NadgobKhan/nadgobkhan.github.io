---
title: Compfest 15 - Read Around
date: 2023-11-23 17:00:00 -0200
categories: [CTF Write-ups, Web]
tags: [ctf, web, compfest-15]     # TAG names should always be lowercase
---

## Abstract
The web application suffered from buffer overflow vulnerability present in `collections.deque`, whose maximum length was set to the value of `Content-Length`, which I had control of. 
## Solution
The web application featured a form where users could enter a file name, and upon submission, the server would provide the corresponding file content if the file existed.

After reading the code, I got the following:

- the contents of the body were read in chunks of “8196” byte and were saved in the variable “body”
- the variable body must not begin with “fname=/”
- after each iteration, the contents of the body were appended to the variable “data_buffer”

Before the reading operation, the entire content of the “data” variable (which was a string containing everything after headers) was saved in the “data_buffer” variable, which was of type `collections.deque`. The main vulnerability of the code was that `data_buffer` was bound to the specified length given in `maxlen`.

```python
data_buffer: collections.deque[str] = collections.deque(maxlen=content_length)
```

Since we control the value of the header `Content-Length`, we also control the maximum length of the `data_buffer`.

The goal was to be able to read the file `/flag.txt`, which meant being able to send a request containing the `fname=/flag.txt` in the body.

The `Request` object was returned as

`return Request(method, path, unquote("".join(list(data_buffer))))`, which meant I could put anything in the actual body of the request, which was saved in the `data` variable.

As such, I had to do the following:

1. modify the `Content-Length` header to the value of 15 (the length of the string `fname=/flag.txt`)
2. include in the body of the request more than 15 characaters while making sure that `fname=flag.txt` was not the first parameter.

## Final Step
In the end, I sent the following request:

```python
POST / HTTP/2
Host: 34.101.68.243:10013
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
Origin: http://34.101.68.243:10013
DNT: 1
Connection: close
Referer: http://34.101.68.243:10013/
Upgrade-Insecure-Requests: 1

t=a&fname=/flag.txt
```

The total length of the data part of the request (`t=a&fname=/flag.txt`) is 19 characters, meaning the following code will not execute:

```python
while data_len < content_length:
        body = (await reader.read(BUFFER_SIZE)).decode("utf8")
        if unquote(body).startswith("fname=/"):
            raise InvalidRequest("Can't do that.")

        data_buffer.extend(list(body))
        data_len += len(body)
```

since the length of the data is larger than the value of `Content-Length`. That means the backend will attempt to save the entire string `t=a&fname=/flag.txt` in the variable `data_buffer`, but since the maximum length of it is 15, as per the documentation, items will be discarded from the left side in order to make space for the rest of the string! That means `t=a&` will be discarded and the last 4 characters will be added to `data_buffer`, making the `[Request.data]` be equal to `fname=/flag.txt`, just like I wanted!

After sending that request, I got the flag: `COMPFEST15{P4rs1Ng_RFC_is_h4rd_14593de95e7}`