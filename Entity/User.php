<?php
namespace Yucca\Bundle\FosUserAdapterBundle\Entity;

use FOS\UserBundle\Model\GroupableInterface;
use FOS\UserBundle\Model\GroupInterface;
use FOS\UserBundle\Model\UserInterface as BaseUserInterface;
use Yucca\Model\ModelAbstract;

/**
 * Class User
 *
 * @package Yucca\Bundle\FosUserAdapterBundle\Entity
 */
abstract class User extends ModelAbstract implements UserInterface, GroupableInterface
{
    protected $yuccaProperties = array('id','username','usernameCanonical','email','emailCanonical','enabled','salt','password','lastLogin','confirmationToken','passwordRequestedAt',/*'groups',*/'locked','expired','expiresAt','roles','credentialsExpired','credentialsExpireAt');

    protected $id;

    /**
     * @var string
     */
    protected $username;

    /**
     * @var string
     */
    protected $usernameCanonical;

    /**
     * @var string
     */
    protected $email;

    /**
     * @var string
     */
    protected $emailCanonical;

    /**
     * @var boolean
     */
    protected $enabled = false;

    /**
     * The salt to use for hashing
     *
     * @var string
     */
    protected $salt;

    /**
     * Encrypted password. Must be persisted.
     *
     * @var string
     */
    protected $password;

    /**
     * Plain password. Used for model validation. Must not be persisted.
     *
     * @var string
     */
    protected $plainPassword;

    /**
     * @var \DateTime
     */
    protected $lastLogin;

    /**
     * Random string sent to the user email address in order to verify it
     *
     * @var string
     */
    protected $confirmationToken;

    /**
     * @var \DateTime
     */
    protected $passwordRequestedAt;

    /**
     * @var array
     */
    protected $groups;

    /**
     * @var boolean
     */
    protected $locked = false;

    /**
     * @var boolean
     */
    protected $expired = false;

    /**
     * @var \DateTime
     */
    protected $expiresAt;

    /**
     * @var array
     */
    protected $roles = array();

    /**
     * @var boolean
     */
    protected $credentialsExpired = false;

    /**
     * @var \DateTime
     */
    protected $credentialsExpireAt;

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->salt = base_convert(sha1(uniqid(mt_rand(), true)), 16, 36);
    }

    /**
     * @param string $role
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function addRole($role)
    {
        $this->hydrate('roles');
        $role = strtoupper($role);
        if ($role === static::ROLE_DEFAULT) {
            return $this;
        }

        if (!in_array($role, $this->roles, true)) {
            $this->roles[] = $role;
        }

        return $this;
    }

    /**
     * Serializes the user.
     *
     * The serialized data have to contain the fields used by the equals method and the username.
     *
     * @return string
     */
    public function serialize()
    {
        return serialize(array(
            $this->password,
            $this->salt,
            $this->usernameCanonical,
            $this->username,
            $this->expired,
            $this->locked,
            $this->credentialsExpired,
            $this->enabled,
            $this->id,
        ));
    }

    /**
     * Unserializes the user.
     *
     * @param string $serialized
     */
    public function unserialize($serialized)
    {
        $data = unserialize($serialized);
        // add a few extra elements in the array to ensure that we have enough keys when unserializing
        // older data which does not include all properties.
        $data = array_merge($data, array_fill(0, 2, null));

        list(
            $this->password,
            $this->salt,
            $this->usernameCanonical,
            $this->username,
            $this->expired,
            $this->locked,
            $this->credentialsExpired,
            $this->enabled,
            $this->id
            ) = $data;
    }

    /**
     * Removes sensitive data from the user.
     */
    public function eraseCredentials()
    {
        $this->plainPassword = null;
    }

    /**
     * Returns the user unique id.
     *
     * @return mixed
     */
    public function getId()
    {
        $this->hydrate('id');

        return $this->id;
    }

    /**
     * @return string
     */
    public function getUsername()
    {
        $this->hydrate('username');

        return $this->username;
    }

    /**
     * @return string
     */
    public function getUsernameCanonical()
    {
        $this->hydrate('usernameCanonical');

        return $this->usernameCanonical;
    }

    /**
     * @return null|string
     */
    public function getSalt()
    {
        $this->hydrate('salt');

        return $this->salt;
    }

    /**
     * @param null|string $salt
     * @return $this
     */
    public function setSalt($salt)
    {
        $this->hydrate('salt');

        $this->salt = $salt;
        return $this;
    }

    /**
     * @return string
     */
    public function getEmail()
    {
        $this->hydrate('email');

        return $this->email;
    }

    /**
     * @return string
     */
    public function getEmailCanonical()
    {
        $this->hydrate('emailCanonical');

        return $this->emailCanonical;
    }

    /**
     * Gets the encrypted password.
     *
     * @return string
     */
    public function getPassword()
    {
        $this->hydrate('password');

        return $this->password;
    }

    /**
     * @return string
     */
    public function getPlainPassword()
    {
        //Not stored to DB
        return $this->plainPassword;
    }

    /**
     * Gets the last login time.
     *
     * @return \DateTime
     */
    public function getLastLogin()
    {
        $this->hydrate('lastLogin');

        return $this->lastLogin;
    }

    /**
     * @return string
     */
    public function getConfirmationToken()
    {
        $this->hydrate('confirmationToken');

        return $this->confirmationToken;
    }

    /**
     * Returns the user roles
     *
     * @return array The roles
     */
    public function getRoles()
    {
        $this->hydrate('roles');
        $roles = $this->roles;

        foreach ($this->getGroups() as $group) {
            $roles = array_merge($roles, $group->getRoles());
        }

        // we need to make sure to have at least one role
        $roles[] = static::ROLE_DEFAULT;

        return array_unique($roles);
    }

    /**
     * Never use this to check if this user has access to anything!
     *
     * Use the SecurityContext, or an implementation of AccessDecisionManager
     * instead, e.g.
     *
     *         $securityContext->isGranted('ROLE_USER');
     *
     * @param string $role
     *
     * @return boolean
     */
    public function hasRole($role)
    {
        return in_array(strtoupper($role), $this->getRoles(), true);
    }

    /**
     * @return bool
     */
    public function isAccountNonExpired()
    {
        $this->hydrate('expired');
        if (true === $this->expired) {
            return false;
        }

        $this->hydrate('expiresAt');
        if (null !== $this->expiresAt && $this->expiresAt->getTimestamp() < time()) {
            return false;
        }

        return true;
    }

    /**
     * @return bool
     */
    public function isAccountNonLocked()
    {
        $this->hydrate('locked');

        return !$this->locked;
    }

    /**
     * @return bool
     */
    public function isCredentialsNonExpired()
    {
        $this->hydrate('credentialsExpired');
        if (true === $this->credentialsExpired) {
            return false;
        }

        $this->hydrate('credentialsExpireAt');
        if (null !== $this->credentialsExpireAt && $this->credentialsExpireAt->getTimestamp() < time()) {
            return false;
        }

        return true;
    }

    /**
     * @return bool
     */
    public function isCredentialsExpired()
    {
        return !$this->isCredentialsNonExpired();
    }

    /**
     * @return bool
     */
    public function isEnabled()
    {
        $this->hydrate('enabled');

        return $this->enabled;
    }

    /**
     * @return bool
     */
    public function isExpired()
    {
        return !$this->isAccountNonExpired();
    }

    /**
     * @return bool
     */
    public function isLocked()
    {
        return !$this->isAccountNonLocked();
    }

    /**
     * @return bool
     */
    public function isSuperAdmin()
    {
        return $this->hasRole(static::ROLE_SUPER_ADMIN);
    }

    /**
     * @param UserInterface $user
     *
     * @return bool
     */
    public function isUser(BaseUserInterface $user = null)
    {
        return null !== $user && $this->getId() === $user->getId();
    }

    /**
     * @param string $role
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function removeRole($role)
    {
        $this->hydrate('roles');
        if (false !== $key = array_search(strtoupper($role), $this->roles, true)) {
            unset($this->roles[$key]);
            $this->roles = array_values($this->roles);
        }

        return $this;
    }

    /**
     * @param string $username
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setUsername($username)
    {
        $this->hydrate('username');
        $this->username = $username;

        return $this;
    }

    /**
     * @param string $usernameCanonical
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setUsernameCanonical($usernameCanonical)
    {
        $this->hydrate('usernameCanonical');
        $this->usernameCanonical = $usernameCanonical;

        return $this;
    }

    /**
     * @param \DateTime $date
     *
     * @return User
     */
    public function setCredentialsExpireAt(\DateTime $date = null)
    {
        $this->hydrate('credentialsExpireAt');
        $this->credentialsExpireAt = $date;

        return $this;
    }

    /**
     * @param boolean $boolean
     *
     * @return User
     */
    public function setCredentialsExpired($boolean)
    {
        $this->hydrate('credentialsExpired');
        $this->credentialsExpired = $boolean;

        return $this;
    }

    /**
     * @param string $email
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setEmail($email)
    {
        $this->hydrate('email');
        $this->email = $email;

        return $this;
    }

    /**
     * @param string $emailCanonical
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setEmailCanonical($emailCanonical)
    {
        $this->hydrate('emailCanonical');
        $this->emailCanonical = $emailCanonical;

        return $this;
    }

    /**
     * @param bool $boolean
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setEnabled($boolean)
    {
        $this->hydrate('enabled');
        $this->enabled = (Boolean) $boolean;

        return $this;
    }

    /**
     * Sets this user to expired.
     *
     * @param Boolean $boolean
     *
     * @return User
     */
    public function setExpired($boolean)
    {
        $this->hydrate('expired');
        $this->expired = (Boolean) $boolean;

        return $this;
    }

    /**
     * @param \DateTime $date
     *
     * @return User
     */
    public function setExpiresAt(\DateTime $date = null)
    {
        $this->hydrate('expiresAt');
        $this->expiresAt = $date;

        return $this;
    }

    /**
     * @param string $password
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setPassword($password)
    {
        $this->hydrate('password');
        $this->password = $password;

        return $this;
    }

    /**
     * @param bool $boolean
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setSuperAdmin($boolean)
    {
        if (true === $boolean) {
            $this->addRole(static::ROLE_SUPER_ADMIN);
        } else {
            $this->removeRole(static::ROLE_SUPER_ADMIN);
        }

        return $this;
    }

    /**
     * @param string $password
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setPlainPassword($password)
    {
        //Not saved to DB
        $this->plainPassword = $password;

        return $this;
    }

    /**
     * @param \DateTime $time
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setLastLogin(\DateTime $time = null)
    {
        $this->hydrate('lastLogin');
        $this->lastLogin = $time;

        return $this;
    }

    /**
     * @param bool $boolean
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setLocked($boolean)
    {
        $this->hydrate('locked');
        $this->locked = $boolean;

        return $this;
    }

    /**
     * @param string $confirmationToken
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setConfirmationToken($confirmationToken)
    {
        $this->hydrate('confirmationToken');
        $this->confirmationToken = $confirmationToken;

        return $this;
    }

    /**
     * @param \DateTime $date
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setPasswordRequestedAt(\DateTime $date = null)
    {
        $this->hydrate('passwordRequestedAt');
        $this->passwordRequestedAt = $date;

        return $this;
    }

    /**
     * Gets the timestamp that the user requested a password reset.
     *
     * @return null|\DateTime
     */
    public function getPasswordRequestedAt()
    {
        $this->hydrate('passwordRequestedAt');

        return $this->passwordRequestedAt;
    }

    /**
     * @param int $ttl
     *
     * @return bool
     */
    public function isPasswordRequestNonExpired($ttl)
    {
        return $this->getPasswordRequestedAt() instanceof \DateTime &&
        $this->getPasswordRequestedAt()->getTimestamp() + $ttl > time();
    }

    /**
     * @param array $roles
     *
     * @return $this|\FOS\UserBundle\Model\UserInterface
     */
    public function setRoles(array $roles)
    {
        $this->hydrate('roles');
        $this->roles = array();

        foreach ($roles as $role) {
            $this->addRole($role);
        }

        return $this;
    }

    /**
     * Gets the groups granted to the user.
     *
     * @return Collection
     */
    public function getGroups()
    {
        return $this->groups ?: $this->groups = array();
    }

    /**
     * @return array
     */
    public function getGroupNames()
    {
        $names = array();
        foreach ($this->getGroups() as $group) {
            $names[] = $group->getName();
        }

        return $names;
    }

    /**
     * @param string $name
     *
     * @return boolean
     */
    public function hasGroup($name)
    {
        return in_array($name, $this->getGroupNames());
    }

    /**
     * @param GroupInterface $group
     *
     * @return $this|GroupableInterface
     */
    public function addGroup(GroupInterface $group)
    {
        if (!$this->getGroups()->contains($group)) {
            $this->getGroups()->add($group);
        }

        return $this;
    }

    /**
     * @param GroupInterface $group
     *
     * @return $this|GroupableInterface
     */
    public function removeGroup(GroupInterface $group)
    {
        if ($this->getGroups()->contains($group)) {
            $this->getGroups()->removeElement($group);
        }

        return $this;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return (string) $this->getUsername();
    }
}
