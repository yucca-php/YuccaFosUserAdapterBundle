<?php
namespace Yucca\Bundle\FosUserAdapterBundle\Manager;
use Yucca\Bundle\FosUserAdapterBundle\Entity\UserInterface;
use FOS\UserBundle\Model\UserManager as BaseUserManager;
use Yucca\Component\EntityManager;
use Yucca\Component\Selector\SelectorInterface;
use FOS\UserBundle\Model\UserInterface as BaseUserInterface;

/**
 * Class UserManager
 *
 * @package Yucca\Bundle\FosUserAdapterBundle\Manager
 */
class UserManager extends BaseUserManager
{
    /**
     * @var EntityManager
     */
    protected $yuccaEntityManager;
    /**
     * @var boolean $findUsersEnabled
     */
    protected $findUsersEnabled;
    /**
     * @var string $modelClassName
     */
    protected $modelClassName;
    /**
     * @var string $selectorClassName
     */
    protected $selectorClassName;

    /**
     * @param bool $findUsersEnabled
     */
    public function setFindUsersEnabled($findUsersEnabled=false)
    {
        $this->findUsersEnabled = $findUsersEnabled;
    }

    /**
     * @param EntityManager $yuccaEntityManager
     */
    public function setYuccaEntityManager(EntityManager $yuccaEntityManager)
    {
        $this->yuccaEntityManager = $yuccaEntityManager;
    }

    /**
     * @param string $modelClassName
     */
    public function setModelClassName($modelClassName)
    {
        $this->modelClassName = $modelClassName;
    }

    /**
     * @param string $selectorClassName
     */
    public function setSelectorClassName($selectorClassName)
    {
        $this->selectorClassName = $selectorClassName;
    }

    /**
     * @throws \RuntimeException
     * @return \Traversable|void
     */
    public function findUsers()
    {
        if (false===$this->findUsersEnabled) {
            throw new \RuntimeException('findUsers is disabled');
        }

    }

    /**
     * @param BaseUserInterface $user
     */
    public function deleteUser(BaseUserInterface $user)
    {
        $this->yuccaEntityManager->remove($user);
    }

    /**
     * @param BaseUserInterface $user
     */
    public function updateUser(BaseUserInterface $user)
    {
        $this->updateCanonicalFields($user);
        $this->updatePassword($user);

        $this->yuccaEntityManager->save($user);

    }

    /**
     * @param array $criteria
     * @return SelectorInterface
     */
    protected function createSelector(array $criteria)
    {
        $selector = $this->yuccaEntityManager->getSelectorManager()->getSelector($this->selectorClassName);

        $selector->setCriteria($criteria);

        return $selector;
    }

    /**
     * @param array $criteria
     *
     * @return \FOS\UserBundle\Model\UserInterface|\Yucca\Model\ModelInterface
     * @throws \RuntimeException
     */
    public function findUserBy(array $criteria)
    {
        $selector = $this->createSelector($criteria);

        if (1 != $selector->count()) {
            return null;
        }

        return $this->yuccaEntityManager->load($this->modelClassName, $selector->current(), $selector->currentShardingKey());
    }

    /**
     * @param int $id
     *
     * @return \FOS\UserBundle\Model\UserInterface|\Yucca\Model\ModelInterface
     * @throws \RuntimeException
     */
    public function findUserById($id)
    {
        return $this->yuccaEntityManager->load($this->modelClassName, $id);
    }

    /**
     * @param BaseUserInterface $user
     */
    public function reloadUser(BaseUserInterface $user)
    {
        $user->reset($user->getId());
    }

    /**
     * @return \FOS\UserBundle\Util\CanonicalizerInterface|string
     */
    public function getClass()
    {
        return $this->modelClassName;
    }
}
