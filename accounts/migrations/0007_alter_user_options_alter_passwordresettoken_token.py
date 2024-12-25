# Generated by Django 5.0.6 on 2024-12-24 19:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_remove_user_password_reset_token_created_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='user',
            options={'verbose_name': 'User', 'verbose_name_plural': 'Users'},
        ),
        migrations.AlterField(
            model_name='passwordresettoken',
            name='token',
            field=models.CharField(max_length=100, unique=True),
        ),
    ]