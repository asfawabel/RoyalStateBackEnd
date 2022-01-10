import User from "../../../models/user";
import config from "../../../utils/config";
import jsonwebtoken from "jsonwebtoken";
import bcryptjs from "bcryptjs";
import { validatePassword } from "../../../utils/validator";

const resetPassword = async (_, { input }) => {
  const { email } = (await jsonwebtoken.verify(
    input.resetToken,
    config.JWT_VERIFICATION_PASSWORD_SECRET
  )) as { email: string };
  if (!email) {
    throw Error("Invalid Token");
  }
  const user = await User.query().select("id").findOne("email", "=", email);

  if (!user) {
    throw Error("Invalid Token");
  }
  //validate password
  if (!validatePassword(input.newPassword)) {
    throw Error("Invalid New Password");
  }

  //change password
  if (
    await user.$query().patch({
      password: await bcryptjs.hash(input.newPassword, config.SALT_ROUNDS),
    })
  ) {
    return true;
  }
  return false;
};

export default resetPassword;
