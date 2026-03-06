# 21


```shell
 62         runtime.GC()
 63 
 64         cpuProfileBuff := &bytes.Buffer{}
 65 
 66         err := pprof.StartCPUProfile(cpuProfileBuff)
 67 
 68         if err != nil {
 69 
 70                 panic(err)
 71         }
 72 
 73         time.Sleep(time.Second * time.Duration(waits))
 74 
 75         pprof.StopCPUProfile()
 76 
 77         runtime.GC()
 78 
 79         profileBytes := cpuProfileBuff.Bytes()
 80 
 81         f, err := os.OpenFile("go.prof", os.O_CREATE|os.O_RDWR, 0644)
 82 


```

# 22

```shell

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                   
  13784 seantyw+  20   0 1226856   4568   1536 S 107.3   0.1   0:22.65 test.out                  
   2903 seantyw+  20   0   11.1g  75580  45056 S   9.3   0.9   0:04.94 node                      
   2797 seantyw+  20   0   11.3g 102748  47872 R   6.0   1.3   0:05.74 node                      
   3718 seantyw+  20   0   31.3g 142516  55296 S   3.3   1.8   0:10.09 node          
```

# 23

```shell
$ ls
2504-03.xyz.md  go.prof  main.go  Makefile  test.out


$ sudo apt update && sudo apt install graphviz


$ go tool pprof -png go.prof
Generating report in profile001.png
```

# 24

```shell
94 type NullStruct struct {
95         Value int
96         Field *NullStruct
97 }


121 
122                 null := NullStruct{}
123 
124                 fmt.Printf("val: %d\n", null.Field.Value)
125 

```

# 25 
 
```shell
$ ./test.out 2
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x4b7593]


```