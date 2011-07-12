(** Unit tests *)
open OUnit
  
let suite = "Borderline" >::: 
  [ 
    Ipset.tests;
  ]     

let _ =         
  Random.self_init ();
  let _ = run_test_tt_main suite in
  ()
    
