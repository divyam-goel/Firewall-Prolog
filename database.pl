:- discontiguous drop/1.
:- discontiguous reject/1.

/* Adapter */
adapter("A").
adapter("B").
adapter("C").
adapter("D").
adapter("E").
adapter("F").
adapter("G").
adapter("H").
adapter("I").
adapter("J").
adapter("K").
adapter("L").
adapter("M").
adapter("N").
drop(adapter("O")).
adapter("P").
reject(adapter("any")).

reject(range(adapter("A"), adapter("C"))).
drop(range(adapter("E"), adapter("G"))).

/*Ethernet */
reject(ethernet(10, 14)).
drop(ethernet(44, 23)).
reject(ethernet(75, _)).
drop(ethernet(_, 63)).

/* IP */
reject(ip(addr(192, 168, 10, 1), src, icmp(1))).
reject(ip(addr(193, 162, 44, 222), _, icmp(4))).
reject(ip(addr(196, 122, 76, 46), dst, _)).
reject(range(ip(addr(192, 168, 10, 1), src, icmp(1)), ip(addr(193, 168, 10, 1), src, icmp(1)))).
reject(range(ip(addr(192, 168, 10, 1), _, icmp(2)), ip(addr(193, 168, 10, 1), _, icmp(2)))).
drop(range(ip(addr(192, 168, 10, 1), src, _), ip(addr(193, 168, 10, 1), src, _))).

/* IPv6 */
reject(ip(addr(345, 5168, 256, 2326, 447, 4734, 573, 11), src, icmp(6))).
drop(ip(addr(345, 5168, 256, 2326, 447, 4734, 573, 11), src, icmp(6))).


/* TCP */
reject(tcp(67)).
drop(tcp(21)).

/* UDP */
drop(udp(78)).
reject(udp(37)).

/* ICMP */
drop(icmp(11, _)).
reject(icmp(_, 24)).
reject(icmp(35,55)).
drop(icmp(43,56)).


/* Danger Zone */
reject(debug).
drop(debug).

/*
adapter(_).
ethernet(_, _).
ip(_, _, _, _).
ipv6(_, _, _, _, _, _, _, _).
tcp(_).
udp(_).
icmp(_, _).
icmpv6(_, _).
*/
