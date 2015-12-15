BEGIN {
    FS=","
}

{
    gsub(" ", "", $0)
    # table_id = "\"table_id\":"0""
    table_id = "\"table_id\":"2""
    cookie = "\"cookie\":"$1""
    priority = "\"priority\":"$1""
    actions = "\"actions\":[{\"type\":\"OUTPUT\",\"port\":\"2\"}]"
    dl_type = "\"dl_type\":2048"
    ip_src = "\"ipv4_src\":\""strtonum("0x"substr($2,1,2))"."strtonum("0x"substr($2,3,2))"."strtonum("0x"substr($2,5,2))"."strtonum("0x"substr($2,7,2))"/"strtonum("0x"substr($3,1,2))"."strtonum("0x"substr($3,3,2))"."strtonum("0x"substr($3,5,2))"."strtonum("0x"substr($3,7,2))"\""
    ip_dst = "\"ipv4_dst\":\""strtonum("0x"substr($4,1,2))"."strtonum("0x"substr($4,3,2))"."strtonum("0x"substr($4,5,2))"."strtonum("0x"substr($4,7,2))"/"strtonum("0x"substr($5,1,2))"."strtonum("0x"substr($5,3,2))"."strtonum("0x"substr($5,5,2))"."strtonum("0x"substr($5,7,2))"\""

    l4_match = ""
    if ($14 != "00") {
	ip_proto = "\"ip_proto\":"strtonum("0x"$10)
	l4_match = ","ip_proto
	    if ($11 != "0000" || $13 != "0000") {
		metadata = "\"metadata\":\"0x00000000"$6$8"/0x00000000"$7$9"\""
		l4_match = l4_match","metadata
	    }
    }
    str = "{"table_id","priority","cookie","actions",\"match\":{"dl_type","ip_src","ip_dst""l4_match"}}";
    print str;
}
