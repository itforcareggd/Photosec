from django import forms

CHECKBOX_CHOICES = [
    ('checked', '')
]


class FilesForm(forms.Form):
    delete = forms.MultipleChoiceField(
        choices=CHECKBOX_CHOICES,
        widget=forms.CheckboxSelectMultiple(),
    )
