const { beforeUserCreated } = require("firebase-functions/v2/identity");

exports.beforeCreate = beforeUserCreated((event) => ({
  displayName: JSON.stringify({ locale: event.locale, disabled: event.data.disabled }),
}));
