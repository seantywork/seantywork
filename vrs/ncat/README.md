# 

```shell

tricky to use globals

```

# 

```shell


error[E0381]: used binding `ncat_opts` is possibly-uninitialized
  --> src/main.rs:66:20
   |
14 |     let ncat_opts: NCAT::NcatOptions;
   |         --------- binding declared here but left uninitialized
...
55 |             ncat_opts = arcno.as_ref().clone();
   |             --------- binding initialized here in some conditions
...
66 |     println!("{}", ncat_opts.host);


```