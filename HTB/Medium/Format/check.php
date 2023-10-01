<?php 
	
	while(true){
	
		$str=readline("enter blog name: "); 

		if(!preg_match('/^[a-z]+$/', $str) || strlen($str) > 50) {
        		echo"Invalid blog name\n";
		}else{
			echo"Working\n";
		}
	}

?>
