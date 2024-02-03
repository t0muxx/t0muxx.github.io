+++
author = "t0muxx"
categories = ["Writeup", "Reverse"]
date = "2024-02-03T06:00:00Z"
tags = ["ObjectiveC", "Obfuscation"]
title = "Dynamically resolving objective-C"
+++

One of the first thing I learnt when I've gotten into obfuscation technique for Windows PE, was the dynamic API calls.
It allows to "hide" the import of WinAPI functions. It can even be combined with "xor" (or more complex) strings hiding techniques to hide traces of suspicious calls.
Indeed this technique is pretty easily circumvent, but I was curious if it was possible to do the same for Objective-C.

## Classic method calls

Let's say we want to call the method `URLWithString` from the class `NSUrl`.
Usually we would write :

```objc
    NSURL *url = [NSURL URLWithString:@"https://api.example.com/data"];
```

This will reflect in the symbol table with :

```
U _OBJC_CLASS_$_NSURL
```

And this seems pretty logic. Let's try to call this method dynamically.

## Dynamic call

To dynamically call a method from a class, we'll need three functions calls :

- `objc_getClass` -> Returns the class object
- `sel_registerName` -> Returns a selector (specifying which method will be called) from the method name.
- `objc_msgSend` -> Send a message to a class.

The code is utterly simple, the only tricky thing is the `objc_msgSend` cast.
`objc_msgSend` is prototyped as `void objc_msgSend(void)` in headers. It is required to cast it, in order to be able to pass its arguments.

```objc
        id NSURLClass = objc_getClass("NSURL");
	    SEL sel = sel_registerName("URLWithString:");
        id url = ((id (*)(id, SEL, id)) objc_msgSend)(NSURLClass, sel, @"http://127.0.0.1:8000");
```

Now, We can't see `NSUrl` in the symbols table.

If we apply this technique on a code sending an HTTP request through `NSURL*` methods :

```objc
int main() {
        NSLog(@"starting....");
        @autoreleasepool {
        // Create a URL
        //NSURL *url = [NSURL URLWithString:@"https://api.example.com/data"];
        id NSURLClass = objc_getClass("NSURL");
	    SEL sel = sel_registerName("URLWithString:");
        id url = ((id (*)(id, SEL, id)) objc_msgSend)(NSURLClass, sel, @"http://127.0.0.1:8000");

        // Create a URL request
        //NSURLRequest *request = [NSURLRequest requestWithURL:url];
        id NSURLRequestClass = objc_getClass("NSURLRequest");
        id request = ((id (*)(id, SEL, id)) objc_msgSend)(NSURLRequestClass, @selector(requestWithURL:), url);

        // Send a synchronous request
        NSHTTPURLResponse *response = nil;
        NSError *error = nil;
        // NSData *data = [NSURLConnection sendSynchronousRequest:request
        //                                      returningResponse:&response
        //                                                  error:&error];
        id NSURLConnectionClass = objc_getClass("NSURLConnection");
        id data = ((id (*)(id, SEL, id, id, id)) objc_msgSend)(NSURLConnectionClass, @selector(sendSynchronousRequest:returningResponse:error:), request, &response, &error);

        if (error) {
            NSLog(@"Error: %@", error.localizedDescription);
        } else {
            // Handle the response data
            NSString *responseData = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            NSLog(@"Response Data: %@", responseData);

            // You can also access the response status code
            NSInteger statusCode = [response statusCode];
            NSLog(@"Status Code: %ld", (long)statusCode);
        }
    }
    NSLog(@"ENd");
    return 0;
}
```

After compiling, we can observe the symbol table using `nm` and notice no references to `NSURL*` :

```
00000001000038a0 T _FSLog
                 U _NSLog
                 U _OBJC_CLASS_$_NSDate
                 U _OBJC_CLASS_$_NSDateFormatter
                 U _OBJC_CLASS_$_NSFileHandle
                 U _OBJC_CLASS_$_NSFileManager
                 U _OBJC_CLASS_$_NSString
                 U ___CFConstantStringClassReference
0000000100000000 T __mh_execute_header
00000001000080c0 b _dateFormatter
00000001000080d0 b _logHandle
00000001000080c8 b _logManager
0000000100003710 T _main
                 U _objc_alloc
                 U _objc_alloc_init
                 U _objc_autoreleasePoolPop
                 U _objc_autoreleasePoolPush
                 U _objc_getClass
                 U _objc_msgSend
0000000100003b6c s _objc_msgSend$dataUsingEncoding:
0000000100003b8c s _objc_msgSend$date
0000000100003bac s _objc_msgSend$defaultManager
0000000100003bcc s _objc_msgSend$fileExistsAtPath:
0000000100003bec s _objc_msgSend$fileHandleForWritingAtPath:
0000000100003c0c s _objc_msgSend$initWithData:encoding:
0000000100003c2c s _objc_msgSend$initWithFormat:arguments:
0000000100003c4c s _objc_msgSend$localizedDescription
0000000100003c6c s _objc_msgSend$lowercaseString
0000000100003c8c s _objc_msgSend$seekToEndOfFile
0000000100003cac s _objc_msgSend$setDateFormat:
0000000100003ccc s _objc_msgSend$statusCode
0000000100003cec s _objc_msgSend$stringFromDate:
0000000100003d0c s _objc_msgSend$stringWithFormat:
0000000100003d2c s _objc_msgSend$writeData:
0000000100003d4c s _objc_msgSend$writeToFile:atomically:encoding:error:
                 U _sel_registerName
00000001000080b8 d _writeToLogFile
```

## Conclusion

Short blogpost, as there is nothing fancy here, I just wanted to share this technique.