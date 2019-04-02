const bcrypt = require('bcrypt');
const prompt = require('prompt');

prompt.start();

let schema = {
    properties: {
        password: {
            hidden: true
        },
        hash: {
            hidden: true
        }
    }
}

prompt.get(schema, (err, result) => {
    bcrypt.compare(result.password, result.hash, function(err, result) {
        console.log(result);
    });
})

