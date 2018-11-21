elblog2elasticserch
===================

- - - - 

structure

    [ ELB ] --> [ S3 bucket ] --> [ Lambda ] --> [ Elastic Search Service ]

step

	1. export ELB logs to S3 bucket
	2. build elastic search service
	3. set vpc endpoint for S3
	4. create lambda function
	5. set env and timeout for lambda function
	6. create or assign role for lambda
	7. make and upload function code
