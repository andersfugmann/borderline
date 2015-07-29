(** Unit tests *)
open OUnit2

let suite = "Borderline" >:::
  [
    Ipset.test;
  ]

let _ =
  Random.self_init ();
  let _ = run_test_tt_main suite in
  ()
