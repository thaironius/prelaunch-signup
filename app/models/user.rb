class User < ActiveRecord::Base
  rolify
  # Include default devise modules. Others available are:
  # :token_authenticatable, :encryptable, :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable, :confirmable,
    :recoverable, :rememberable, :trackable, :validatable

  # Setup accessible (or protected) attributes for your model
  attr_accessible :name, :email, :password, :password_confirmation, :remember_me

  # override Devise method
  # no password is required when the account is created; validates password when the user sets one
  validates_confirmation_of :password
  def password_required?
    if !persisted?
      !(password != "")
    else
      !password.nil? || !password_confirmation.nil?
    end
  end

  # overide Devise method
  def confirmation_required?
  	false
  end

  #override Devise method
  def active_for_authentication?
  	confirmed? || confirmation_period_valid?
  end

  def send_reset_password_instructions
  	if self.confirmed?
  		super
  	else
  		errors.add :base, "You must receive an invitation before you set your password."
  	end
  end

end
