void main()
{
	import std.stdio;
	import vibe.aws.dynamodb;
	import vibe.aws.credentials;

	import std.process:environment;
	immutable accessKey = environment["AWS_ACCESS_KEY"];
	immutable secretKey = environment["AWS_SECRET_KEY"];

	auto creds = new StaticAWSCredentials(accessKey, secretKey);
	auto ddb = new DynamoDB("eu-central-1", creds);
	auto table = ddb.table("test");

	auto item1 = Item().set("user", "dddd");
	item1.set("url","test");

	table.put(item1);
}