const Username = () => {
    const prefix = "User";
    const randomDigits = Math.floor(1000000 + Math.random() * 9000000);
    const username = prefix + randomDigits.toString();
    return username;
  }

export { Username };