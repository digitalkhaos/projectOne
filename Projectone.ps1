function Projectone {

		Param([parameter()][switch]$h)
	$script = 'C:\Users\johnl\Documents\Repos\projectOne\projectOne.py'

	$params = @()

	if($h){
		$params += "-h"
	}

	python $script $params

}

