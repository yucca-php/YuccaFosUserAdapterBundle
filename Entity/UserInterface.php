<?php
namespace Yucca\Bundle\FosUserAdapterBundle\Entity;

use FOS\UserBundle\Model\UserInterface as BaseUserInterface;
use Yucca\Model\ModelInterface;

/**
 * Interface UserInterface
 *
 * @package Yucca\Bundle\FosUserAdapterBundle\Entity
 */
interface UserInterface extends BaseUserInterface, ModelInterface
{

}
