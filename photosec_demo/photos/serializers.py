from rest_framework import serializers
from photos.models import Photos


class PhotoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Photos
        fields = ['id', 'title', 'photo']
