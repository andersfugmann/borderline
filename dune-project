(lang dune 3.9)
(using menhir 2.0)
(name borderline)

(generate_opam_files true)

(source (github andersfugmannn/borderline))
(license GPL3)
(maintainers "Anders Fugmann <anders@fugmann.net>")

(package
 (name borderline)
 (authors "Anders Fugmann")
 (synopsis "IPv4 and Ipv6 firewall generator for linux nftables")
 (depends
  (ocaml (>= 4.14.0))
   ounit2
   base
   stdio
   ipaddr
   ppx_deriving
   ppx_compare
   ppx_sexp_conv
   menhir
 )
)
