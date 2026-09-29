// The shape check every closed-record validator in this directory starts from: an ordinary object literal, never an array,
// a null-prototype object, a class instance or a proxied exotic (arrays and class instances fail the prototype test).
export const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;
