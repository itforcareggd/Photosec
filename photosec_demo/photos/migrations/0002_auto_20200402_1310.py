# Generated by Django 3.0.5 on 2020-04-02 11:10

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('photos', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='photos',
            old_name='Photo',
            new_name='photo',
        ),
    ]