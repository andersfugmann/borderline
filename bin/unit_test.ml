(** Unit tests *)
open OUnit2
open Borderline_lib

let suite = "Borderline" >:::
            [
              Ipset.Test.unittest;
              Predicate.Test.unittest;
            ]

let _ =
  Random.self_init ();
  let _ = run_test_tt_main suite in
  ()
