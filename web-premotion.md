# "premotion" writeup

We have sql injection in "ineq" parameter of REST api request.

After some fuzzing, we can find out that
1) it's sqlite database
2) we can use union select with 4 columns and get the output as json
3) space character is filtered (but /*comment*/ is not)

After dumping table names from sqlite_master we find interesting "s3ekr17_passwords" table with two fields: userid and password. Every password is a single character, we need to concatinate them into a flag using userid as a key. 