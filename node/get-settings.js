var request = require('request');
var path = require('path');

var argv = require('minimist')(process.argv.slice(2));
console.log(argv);

if(argv.help){
  var filename = path.basename(__filename);
  console.log('Usage: '+filename+' --tenant https://xxxdddddd.live.dynatrace.com --token dt0c01.xxx');
  process.exit();
}
if(!argv.token || !argv.tenant){
  console.log('Token or tenant missing')
  process.exit();
}

var tenant = argv.tenant; 
var token = argv.token; 


function printResult(settings){
  settings.forEach(setting => {
    console.log('scope:' + setting.scope +' enabled: '+ setting.value.enabled);
  });
}

function getSettings(settingsKey) {
  var settingsApi = {
    'method': 'GET',
    'url': tenant+'/api/v2/settings/objects?schemaIds=builtin:oneagent.features&fields=objectId,value, updateToken, scope&pageSize=500',
    'headers': {
      'Accept': 'application/json; charset=utf-8',
      'Authorization': 'Api-Token '+token
    }
  };
  
  request(settingsApi, function (error, response) {
    if (error) throw new Error(error);
    
    var settings = JSON.parse(response.body).items.filter(ob => ob.value.key === settingsKey );
    printResult(settings)
  });
}



getSettings('SENSOR_JAVA_CASP_FLAW_FINDER');
