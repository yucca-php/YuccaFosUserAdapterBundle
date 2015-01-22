This bundle is intended to be used with Yucca Orm : https://github.com/rjanot/yucca

Custom configuration:
---------------------

```yaml
fos_user:
    db_driver: custom
    user_class: Acme\Bundle\AcmeBundle\Entity\YurExtendedUser
    service:
        user_manager: acme_user.user.manager
```
