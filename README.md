# checkpassword-pwn
针对pwn 20G+密码库 ，采用二分法查询


The latest password list as of writing is 23GB uncompressed, so a naive text search can be slow and memory-intensive. This program mmaps the file and binary searches over it. This approach is fast and has minor memory usage


参考项目：https://github.com/jbowens/checkpassword
