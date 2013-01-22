export {
  redef enum Notice::Type += {
    TCP::TEST
  };
}

event new_connection(c: connection)
      {
      print fmt("New Connection => Source IP: %s, Source Port: %s, Destination IP: %s, Destination Port: %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);        
         NOTICE([$note=TCP::TEST,$msg="",
                 $conn=c
               ]);
	local cmd = fmt("/usr/local/bro/share/bro/site/test.sh");
	piped_exec(cmd, fmt("%s", c$id$orig_h));
      }
