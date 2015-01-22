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

More informations on https://github.com/FriendsOfSymfony/FOSUserBundle/blob/ef7ca325929ff102fff521653a2e3b88c7a40361/Resources/doc/custom_storage_layer.md
