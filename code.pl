:- include("database.pl").

/* Helper Code */
string_int(String, Integer) :-
	atom_string(Atom, String),
    atom_codes(Atom, Codes),
    number_codes(Integer, Codes).

validate_range(Value, Min, Max):-
	(Value >= Min),
	(Value =< Max).

list_string_int([], []).
list_string_int([H1|T1], [H2|T2]):-
	string_int(H1, H2),
	list_string_int(T1, T2).

list_string_codes([], []).
list_string_codes([H1|T1], [H2|T2]):-
	string_codes(H1, [H2]),
	list_string_codes(T1, T2).

list_range([X,Y], []):- X>Y.
list_range([H,X], [H|T]):-
	H=<X,
	Temp is H+1,
	list_range([Temp,X], T).

substring(X,S) :-
	atom_string(X_atom, X),
	atom_string(S_atom, S),
	atom_concat(_,T,S_atom),
	atom_concat(X_atom,_,T),
	X \= "".

string_range(String, List, 0):-
	substring("-", String),
	split_string(String, "-", "", Range),
	list_string_int(Range, RangeList),
	list_range(RangeList, List).

string_range(String, List, 1):-
	substring("-", String),
	split_string(String, "-", "", Range),
	list_string_codes(Range, RangeList),
	list_range(RangeList, T_List),
	list_string_codes(List, T_List).

string_list(String, List, Check):-
	string_csv(String, List);
	string_range(String, List, Check);
	string_value(String, List).

/* Code */

/* Adapter */
check_adapter(X):-
	reject(X),
	write("Adapter Rejected.\n").

check_adapter(X):-
	drop(X).

check_range_adapter("any"). 

check_range_adapter(Adapter):-
	drop(range(adapter(Min), adapter(Max))),
	Adapter>=Min,
	Adapter=<Max.

check_range_adapter(Adapter):-
	reject(range(adapter(Min), adapter(Max))),
	Adapter>=Min,
	Adapter=<Max,
	write("Adapter Rejected.").

validate_adapter(Adapter, Res):-
	(check_adapter(adapter(Adapter)), Res=false);
	(check_range_adapter(Adapter), Res=false);
	Res=true.

/* Ethernet */
check_ethernet(X):-
	reject(X),
	write("Ethernet Rejected.\n").

check_ethernet(X):-
	drop(X).

check_range_ethernet(Ethrnt_Prtl, Ethrnt_Vid):-
	reject(range(ethernet(Prtl1, Vid1), ethernet(Prtl2, Vid2))),
	Ethrnt_Prtl>=Prtl1,
	Ethrnt_Prtl=<Prtl2,
	Ethrnt_Vid>=Vid1,
	Ethrnt_Vid=<Vid2,
	write("Ethernet Rejected.").

check_range_ethernet(Ethrnt_Prtl, Ethrnt_Vid):-
	drop(range(ethernet(Prtl1, Vid1), ethernet(Prtl2, Vid2))),
	Ethrnt_Prtl>=Prtl1,
	Ethrnt_Prtl=<Prtl2,
	Ethrnt_Vid>=Vid1,
	Ethrnt_Vid=<Vid2.

parse_ethernet(Ethrnt, Ethrnt_Prtl, Ethrnt_Vid):-
	split_string(Ethrnt, ":", "", [Ethrnt_Prtl_str, Ethrnt_Vid_str]),
	string_int(Ethrnt_Prtl_str, Ethrnt_Prtl),
	string_int(Ethrnt_Vid_str, Ethrnt_Vid).

validate_ethernet(Ethernet, Res):-
	parse_ethernet(Ethernet, Ethrnt_Prtl, Ethrnt_Vid),
	((check_ethernet(ethernet(Ethrnt_Prtl, Ethrnt_Vid)), Res=false);
	(check_range_ethernet(Ethrnt_Prtl, Ethrnt_Vid), Res=false);
	Res=true).

/* IP */
check_ip(X):-
	reject(X),
	write("IP Rejected.\n").

check_ip(X):-
	drop(X).

ip_abs_value(Int_A, Int_B, Int_C, Int_D, Value):-
	Value is (256^3 * Int_A) + (256^2 * Int_B) + (256^1 * Int_C) + (256^0 * Int_D).

check_range_ip(X1, X2, X3, X4, IP_Type, ICMP_Type):-
	reject(range(ip(addr(Y1, Y2, Y3, Y4), IP_Type, icmp(ICMP_Type)), ip(addr(Z1, Z2, Z3, Z4), IP_Type, icmp(ICMP_Type)))),
	ip_abs_value(X1, X2, X3, X4, Value),
	ip_abs_value(Y1, Y2, Y3, Y4, Min),
	ip_abs_value(Z1, Z2, Z3, Z4, Max),
	Value >= Min,
	Value =< Max,
	write("IP Rejected.\n").

check_range_ip(X1, X2, X3, X4, IP_Type, ICMP_Type):-
	drop(range(ip(addr(Y1, Y2, Y3, Y4), IP_Type, icmp(ICMP_Type)), ip(addr(Z1, Z2, Z3, Z4), IP_Type, icmp(ICMP_Type)))),
	ip_abs_value(X1, X2, X3, X4, Value),
	ip_abs_value(Y1, Y2, Y3, Y4, Min),
	ip_abs_value(Z1, Z2, Z3, Z4, Max),
	Value >= Min,
	Value =< Max.

parse_ip(IP_addr, IP_Addr1, IP_Addr2, IP_Addr3, IP_Addr4) :-
	split_string(IP_addr, ".", "", [IP_Addr1_str, IP_Addr2_str, IP_Addr3_str, IP_Addr4_str|[]]),
	number_codes(IP_Addr1, IP_Addr1_str),
	number_codes(IP_Addr2, IP_Addr2_str),
	number_codes(IP_Addr3, IP_Addr3_str),
	number_codes(IP_Addr4, IP_Addr4_str).

validate_ip(IP_Addr, IP_Type, ICMP_Type, Res):-
	parse_ip(IP_Addr, IP_Addr1, IP_Addr2, IP_Addr3, IP_Addr4),
	((check_ip(ip(addr(IP_Addr1, IP_Addr2, IP_Addr3, IP_Addr4), IP_Type, icmp(ICMP_Type))), Res=false);
	(check_range_ip(IP_Addr1, IP_Addr2, IP_Addr3, IP_Addr4, IP_Type, ICMP_Type), Res=false);
	Res=true).

/* IPv6 */
check_ipv6(X):-
	reject(X),
	write("IPv6 Rejected.\n").

check_ipv6(X):-
	drop(X).

hexa_append(String, Hexa_String) :-
	string_to_list(String, Codes),
	string_to_list('0x', HexaCode),
	append(HexaCode, Codes, NewCodes),
	string_to_list(Hexa_String, NewCodes).

parse_ipv6(IPv6_Addr, IPv6_Addr1, IPv6_Addr2, IPv6_Addr3, IPv6_Addr4, IPv6_Addr5, IPv6_Addr6, IPv6_Addr7, IPv6_Addr8):-
	split_string(IPv6_Addr, ":", "", [IPv6_Addr1_str, IPv6_Addr2_str, IPv6_Addr3_str, IPv6_Addr4_str, IPv6_Addr5_str, IPv6_Addr6_str, IPv6_Addr7_str, IPv6_Addr8_str|[]]),
	hexa_append(IPv6_Addr1_str, IPv6_Addr1_hexa),
	hexa_append(IPv6_Addr2_str, IPv6_Addr2_hexa),
	hexa_append(IPv6_Addr3_str, IPv6_Addr3_hexa),
	hexa_append(IPv6_Addr4_str, IPv6_Addr4_hexa),
	hexa_append(IPv6_Addr5_str, IPv6_Addr5_hexa),
	hexa_append(IPv6_Addr6_str, IPv6_Addr6_hexa),
	hexa_append(IPv6_Addr7_str, IPv6_Addr7_hexa),
	hexa_append(IPv6_Addr8_str, IPv6_Addr8_hexa),

	string_int(IPv6_Addr1_hexa, IPv6_Addr1),
	string_int(IPv6_Addr2_hexa, IPv6_Addr2),
	string_int(IPv6_Addr3_hexa, IPv6_Addr3),
	string_int(IPv6_Addr4_hexa, IPv6_Addr4),
	string_int(IPv6_Addr5_hexa, IPv6_Addr5),
	string_int(IPv6_Addr6_hexa, IPv6_Addr6),
	string_int(IPv6_Addr7_hexa, IPv6_Addr7),
	string_int(IPv6_Addr8_hexa, IPv6_Addr8).

validate_ipv6(IPv6_Addr, IP_Type, ICMP_Type, Res3):-
	parse_ipv6(IPv6_Addr, IPv6_Addr1, IPv6_Addr2, IPv6_Addr3, IPv6_Addr4, IPv6_Addr5, IPv6_Addr6, IPv6_Addr7, IPv6_Addr8),
	validate_range(IPv6_Addr1, 0, 65535),
	validate_range(IPv6_Addr2, 0, 65535),
	validate_range(IPv6_Addr3, 0, 65535),
	validate_range(IPv6_Addr4, 0, 65535),
	validate_range(IPv6_Addr5, 0, 65535),
	validate_range(IPv6_Addr6, 0, 65535),
	validate_range(IPv6_Addr7, 0, 65535),
	validate_range(IPv6_Addr8, 0, 65535),
	((check_ipv6(ipv6(addr(IPv6_Addr1, IPv6_Addr2, IPv6_Addr3, IPv6_Addr4, IPv6_Addr5, IPv6_Addr6, IPv6_Addr7, IPv6_Addr8), IP_Type, icmpv6(ICMP_Type))), Res3=false);
	Res3=true).

/* TCP */
check_tcp(X):-
	reject(X),
	write("TCP Rejected.\n").

check_tcp(X):-
	drop(X).

validate_tcp(TCP, Res):-
	validate_range(TCP, 0, 65535),
	((check_tcp(tcp(TCP)), Res=false);
	Res=true).

/* UDP */
check_udp(X):-
	reject(X),
	write("UDP Rejected.\n").

check_udp(X):-
	drop(X).

validate_udp(UDP, Res):-
	validate_range(UDP, 0, 65535),
	((check_udp(udp(UDP)), Res=false);
	Res=true).

/* ICMP */
check_icmp(X):-
	reject(X),
	write("ICMP Rejected.\n").

check_icmp(X):-
	drop(X).

parse_icmp(ICMP, ICMP_Type, ICMP_Code):-
	split_string(ICMP, ":", "", [ICMP_Type_str, ICMP_Code_str]),
	string_int(ICMP_Type_str, ICMP_Type),
	string_int(ICMP_Code_str, ICMP_Code).

validate_icmp_common("ICMP", ICMP, ICMP_Type, Res):-
	parse_icmp(ICMP, ICMP_Type, ICMP_Code),
	((check_icmp(icmp(ICMP_Type, ICMP_Code)), Res=false);
	Res=true).

validate_icmp_common("ICMPv6", ICMP, ICMP_Type, Res):-
	parse_icmp(ICMP, ICMP_Type, ICMP_Code),
	((check_icmp(icmp(ICMP_Type, ICMP_Code)), Res=false);
	Res=true).

/* Extras */
validate_port("TCP", TCP, Res):-
	validate_tcp(TCP, Res).

validate_port("UDP", UDP, Res):-
	validate_udp(UDP, Res).

validate_ip_icmp(IP_Addr_X, IP_Type, ICMP, Res1, Res2):-
	split_string(IP_Addr_X, " ", "", ["ip", IP_Addr]),
	split_string(ICMP, " ", "", ["icmp", ICMP_X]),
	validate_icmp_common("ICMP", ICMP_X, ICMP_Type, Res1),
	validate_ip(IP_Addr, IP_Type, ICMP_Type, Res2).

validate_ip_icmp(IP_Addr_X, IP_Type, ICMP, Res1, Res2):-
	split_string(IP_Addr_X, " ", "", ["ipv6", IP_Addr]),
	split_string(ICMP, " ", "", ["icmpv6", ICMP_X]),
	validate_icmp_common("ICMPv6", ICMP_X, ICMP_Type, Res1),
	validate_ipv6(IP_Addr, IP_Type, ICMP_Type, Res2).

/* Request */
request(Adapter, Ethernet, Src_IP, Dst_IP, Src_Port, Dst_Port, Protocol, ICMP):-
	validate_adapter(Adapter, Res1),
	validate_ethernet(Ethernet, Res2),
	validate_ip_icmp(Src_IP, src, ICMP, Res3, Res4),
	validate_ip_icmp(Dst_IP, dst, ICMP, Res5, Res6),
	validate_port(Protocol, Src_Port, Res7),
	validate_port(Protocol, Dst_Port, Res8), !,
	Res1, Res2, Res3, Res4, Res5, Res6, Res7, Res8.