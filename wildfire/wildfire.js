'use strict';

var request = require('request');
var parser = require('fast-xml-parser');

module.exports = function(RED) {

    function Service(config) {
        RED.nodes.createNode(this, config);

        var node = this;

        this.samples = function (params, callback) {

            if (!config.server) {
                callback(new Error('Missing Appliance Hostname/IP'));
                return;
            }
            const server = config.server.trim().toLowerCase() || "wildfire.paloaltonetworks.com";
            if (server == 'wildfire.paloaltonetworks.com') {
                callback(new Error('Cloud Retrieval not Supported, Use your appliance address'));
                return;
            }

            if (!config.apikey) {
                callback(new Error('Missing Apikey'));
                return;
            }

            const body = Object.assign({}, params, {
                apikey: config.apikey
            });
            if (!body.date) {
                callback(new Error('Missing Date'));
                return;
            }

            const uri = 'https://' + ( config.server == 'test' ? 'wildfire.paloaltonetworks.com' : server ) + '/publicapi/get/verdicts/changed';

            request({
                method: 'POST',
                uri: uri,
                json: true,
                body: body
            }, function (error, response, body) {
                if (error || (!response.statusCode == 200)) {
                    return callback(error || new Error('Request Error'));
                }
                try {
                    var json = parser.parse(body);
                    var verdicts = json && json.wildfire && json.wildfire['get-verdict-info'];
                } catch(err) {
                    return callback(err);
                }
            
                if (!verdicts) { return callback(new Error('invalid response')); }
        
                callback(null, verdicts);
            });

        }
    }

    RED.nodes.registerType("wildfire service", Service);
};
