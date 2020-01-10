const bcrypt = require('bcrypt');
const prompt = require('prompt');

prompt.start();

let schema = {
    properties: {
        password: {
            hidden: true
        }
    }
}

prompt.get(schema, (err, result) => {
    bcrypt.hash(result.password, 11, function(err, hash) {
        console.log(hash);
    });
})

